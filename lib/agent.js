// Proof Gatekeeper agent — core logic (framework-free).
//
// Implements the agent interface documented at https://agentgames.zkverify.io/build
// and https://agentgames.zkverify.io/events/proof-gatekeeper :
//   - Incoming: JSON POST envelope, HMAC-SHA256 signature in the
//     `x-agent-games-signature` header, verified against the RAW body before parsing.
//   - Outgoing: { decision: "APPROVE"|"REJECT", reason_code, proof_tx, proof, public_signals }
//     signed with `x-agent-games-signature` over the raw response body.
//   - The Groth16 proof is generated locally with snarkjs from the bundled
//     gatekeeper circuit (circuits/gatekeeper.wasm + gatekeeper_final.zkey).
//
// Items the public pages do NOT document precisely are marked TODO-VERIFY-AFTER-REGISTRATION.

import crypto from 'node:crypto';
import path from 'node:path';

// BN254 (bn128) scalar field prime.
const FIELD_PRIME =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

function wasmPath() {
  return path.join(process.cwd(), 'circuits', 'gatekeeper.wasm');
}
function zkeyPath() {
  return path.join(process.cwd(), 'circuits', 'gatekeeper_final.zkey');
}

// ---------------------------------------------------------------------------
// HMAC secret handling
// ---------------------------------------------------------------------------

// The platform generates a 32-byte secret at agent registration and shows it
// exactly once (Rules §1.3). It is provided to this app via env var.
// Default interpretation: the env value is the literal secret string (UTF-8).
// TODO-VERIFY-AFTER-REGISTRATION: if the dashboard shows the secret as hex and
// expects the raw bytes to be used as the HMAC key, set AGENT_HMAC_SECRET_IS_HEX=1.
export function getSecret() {
  const raw = process.env.AGENT_HMAC_SECRET;
  if (!raw) return null;
  if (process.env.AGENT_HMAC_SECRET_IS_HEX === '1' && /^[0-9a-fA-F]+$/.test(raw)) {
    return Buffer.from(raw, 'hex');
  }
  return Buffer.from(raw, 'utf8');
}

export function hmacSha256(rawBody, secret) {
  return crypto.createHmac('sha256', secret).update(rawBody).digest();
}

// Accepts the signature header in hex, base64, or "sha256=<hex|base64>" form —
// the public docs name the header but not the encoding.
// TODO-VERIFY-AFTER-REGISTRATION: confirm exact signature encoding with a practice task.
export function verifySignature(rawBody, headerValue, secret) {
  if (!headerValue || typeof headerValue !== 'string') return false;
  let value = headerValue.trim();
  if (value.toLowerCase().startsWith('sha256=')) value = value.slice(7).trim();

  const expected = hmacSha256(rawBody, secret);
  const candidates = [];
  if (/^[0-9a-fA-F]{64}$/.test(value)) candidates.push(Buffer.from(value, 'hex'));
  try {
    const b64 = Buffer.from(value, 'base64');
    if (b64.length === 32) candidates.push(b64);
  } catch {
    /* ignore */
  }
  return candidates.some(
    (c) => c.length === expected.length && crypto.timingSafeEqual(c, expected),
  );
}

export function signBody(rawBodyString, secret) {
  // TODO-VERIFY-AFTER-REGISTRATION: response signature encoding assumed hex.
  return hmacSha256(Buffer.from(rawBodyString, 'utf8'), secret).toString('hex');
}

// ---------------------------------------------------------------------------
// Field conversions
// ---------------------------------------------------------------------------

// Convert a value from the task envelope (0x-hex string, decimal string, or
// number) to the decimal-string form snarkjs expects. Values are passed
// unreduced; the witness calculator reduces mod the field prime itself
// (verified in the feasibility test with the full 256-bit VK hash).
export function toFieldDecimal(value) {
  if (typeof value === 'bigint') return value.toString();
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Error('non-finite number');
    return BigInt(Math.trunc(value)).toString();
  }
  if (typeof value === 'string') {
    const v = value.trim();
    if (/^0x[0-9a-fA-F]+$/.test(v)) return BigInt(v).toString();
    if (/^[0-9]+$/.test(v)) return BigInt(v).toString();
    throw new Error(`cannot convert to field element: ${value}`);
  }
  throw new Error(`unsupported field value type: ${typeof value}`);
}

function toBig(value) {
  return BigInt(toFieldDecimal(value));
}

// The live envelope carries a string task_id such as "gk_24_9d1", but the
// circuit needs a field element.
// TODO-VERIFY-AFTER-REGISTRATION: taskId encoding is NOT documented. Current
// scheme: numeric ids pass through unchanged; other strings are hashed with
// SHA-256 and reduced mod the field prime. Verify against a practice task —
// if the platform re-derives public inputs independently, a wrong encoding
// makes proofs fail verification on their side.
export function taskIdToField(taskId) {
  const s = String(taskId ?? '');
  if (/^[0-9]+$/.test(s)) return BigInt(s).toString();
  const digest = crypto.createHash('sha256').update(s, 'utf8').digest('hex');
  return (BigInt('0x' + digest) % FIELD_PRIME).toString();
}

function randomSalt() {
  // 31 random bytes are always below the field prime.
  return BigInt('0x' + crypto.randomBytes(31).toString('hex')).toString();
}

// ---------------------------------------------------------------------------
// Decision logic — mirrors the trap encyclopedia on the track page.
// Circuit semantics (feasibility-verified): decision = AND(all checks).
// ---------------------------------------------------------------------------

export function evaluateTask(input) {
  let registeredVk, proofVk, minimum, publicBalance, expiryBlock, currentBlock;
  let recipient, conditionRecipient, amount, maxTransfer;
  try {
    registeredVk = toBig(input.registered_vk ?? input.registeredVk);
    proofVk = toBig(input.proof_vk ?? input.proofVk);
    minimum = toBig(input.minimum);
    publicBalance = toBig(input.public_balance ?? input.publicBalance);
    expiryBlock = toBig(input.expiry_block ?? input.expiryBlock);
    currentBlock = toBig(input.current_block ?? input.currentBlock);
    recipient = toBig(input.recipient);
    conditionRecipient = toBig(input.condition_recipient ?? input.conditionRecipient);
    amount = toBig(input.amount);
    maxTransfer = toBig(input.max_transfer ?? input.maxTransfer);
  } catch {
    // Fail closed: never approve what we cannot parse.
    return { decision: 0, reason_code: 'INVALID_INPUT' };
  }

  if (proofVk !== registeredVk) return { decision: 0, reason_code: 'VK_SUBSTITUTION' };
  if (publicBalance < minimum) return { decision: 0, reason_code: 'THRESHOLD_MISMATCH' };
  if (recipient !== conditionRecipient)
    return { decision: 0, reason_code: 'RECIPIENT_MISMATCH' };
  if (!(currentBlock < expiryBlock)) return { decision: 0, reason_code: 'EXPIRED_CONDITION' };
  if (amount > maxTransfer) return { decision: 0, reason_code: 'AMOUNT_OVERFLOW' };
  return { decision: 1, reason_code: 'VALID_CONDITION' };
}

function buildCircuitInputs(envelope, input, decision) {
  return {
    registeredVkHash: toFieldDecimal(input.registered_vk ?? input.registeredVk),
    proofVkHash: toFieldDecimal(input.proof_vk ?? input.proofVk),
    minimum: toFieldDecimal(input.minimum),
    publicBalance: toFieldDecimal(input.public_balance ?? input.publicBalance),
    expiryBlock: toFieldDecimal(input.expiry_block ?? input.expiryBlock),
    currentBlock: toFieldDecimal(input.current_block ?? input.currentBlock),
    recipient: toFieldDecimal(input.recipient),
    conditionRecipient: toFieldDecimal(
      input.condition_recipient ?? input.conditionRecipient,
    ),
    amount: toFieldDecimal(input.amount),
    maxTransfer: toFieldDecimal(input.max_transfer ?? input.maxTransfer),
    decision: String(decision),
    taskId: taskIdToField(envelope.task_id ?? envelope.taskId ?? ''),
    salt: randomSalt(),
  };
}

// ---------------------------------------------------------------------------
// PROOF_REUSED seen-set. Serverless instances are stateless, so this is an
// in-memory best-effort cache only (warm instance). Rules §1.2: task IDs are
// idempotency keys — a retry of the SAME task_id is not "reuse"; reuse means
// the same proof_tx arriving under a DIFFERENT task_id.
// TODO-VERIFY-AFTER-REGISTRATION: move this to durable storage (e.g. Vercel KV
// / Upstash) if reuse detection must survive cold starts.
// ---------------------------------------------------------------------------
const seenProofs = new Map(); // proof_tx -> task_id

// ---------------------------------------------------------------------------
// Main task handler. rawBody: Buffer of the exact request bytes.
// Returns { status, body (object), rawResponse (string), responseSignature }.
// ---------------------------------------------------------------------------
export async function handleTask(rawBody, signatureHeader) {
  const secret = getSecret();
  if (!secret) {
    return respond(500, { error: 'AGENT_HMAC_SECRET is not configured' }, null);
  }
  // Verify BEFORE parsing (Build guide §02).
  if (!verifySignature(rawBody, signatureHeader, secret)) {
    return respond(401, { error: 'invalid signature' }, secret);
  }

  let envelope;
  try {
    envelope = JSON.parse(rawBody.toString('utf8'));
  } catch {
    return respond(400, { error: 'invalid JSON body' }, secret);
  }

  const input = envelope.input ?? envelope;
  const taskId = envelope.task_id ?? envelope.taskId ?? null;
  const proofTx = input.proof_tx ?? input.proofTx ?? null;

  const { decision, reason_code } = evaluateTask(input);

  // Proof-reuse trap: same proof reference under a different task id.
  // Track page: "PROOF_REUSED tasks have no proof to submit and are excluded",
  // so this branch deliberately returns no proof.
  if (proofTx && seenProofs.has(proofTx) && seenProofs.get(proofTx) !== String(taskId)) {
    return respond(
      200,
      { task_id: taskId, decision: 'REJECT', reason_code: 'PROOF_REUSED', proof_tx: proofTx },
      secret,
    );
  }

  const body = {
    task_id: taskId,
    decision: decision === 1 ? 'APPROVE' : 'REJECT',
    reason_code,
    proof_tx: proofTx,
  };

  // Generate the Groth16 proof of our decision (skipped only when the inputs
  // were unparsable — there is nothing meaningful to prove then).
  if (reason_code !== 'INVALID_INPUT') {
    const circuitInputs = buildCircuitInputs(envelope, input, decision);
    const { groth16 } = await import('snarkjs');
    const { proof, publicSignals } = await groth16.fullProve(
      circuitInputs,
      wasmPath(),
      zkeyPath(),
    );
    body.proof = proof;
    body.public_signals = publicSignals;
  }

  if (proofTx) seenProofs.set(proofTx, String(taskId));
  return respond(200, body, secret);
}

function respond(status, body, secret) {
  const rawResponse = JSON.stringify(body);
  return {
    status,
    body,
    rawResponse,
    responseSignature: secret ? signBody(rawResponse, secret) : null,
  };
}
