// Proof Gatekeeper agent — core logic (framework-free).
//
// === AUDIT PATCH 2026-11-16 (NOT DEPLOYED — review copy) ===
// Changes vs the deployed 6e707fc version, each marked [AUDIT-PATCH] below:
//   P1. Trap precedence aligned with the live-validated reference flow
//       (subastian1998/agent-games-season-01): VK_SUBSTITUTION ->
//       PROOF_REUSED -> THRESHOLD_MISMATCH -> EXPIRED_CONDITION ->
//       RECIPIENT_MISMATCH -> AMOUNT_OVERFLOW. (Likely moot if tasks are
//       single-trap by construction, but costs nothing to match.)
//   P2. Durable PROOF_REUSED seen-set + per-task response cache via an
//       optional Upstash/Vercel-KV REST store (env-gated, fail-open,
//       1.2 s timeout). In-memory maps remain as L1. Without env vars the
//       behaviour is exactly the old in-memory best-effort.
//   P3. Field parsing hardening: "0X" prefix accepted; bare hex (>= 40
//       chars containing a-f) accepted for address/VK-style fields;
//       non-integer numbers are rejected instead of silently truncated.
//   P4. Proof-skip guard corrected: the old absolute 2^70 guard did not
//       match the circuit's real limits (measured 2026-11-16: the
//       threshold comparison only proves when |balance - minimum| fits
//       ~32 bits; other comparisons tolerate large absolute values when
//       their difference is small). Witness failure is fast and caught,
//       so the guard now only skips when a compared field is >= the
//       field prime (where reduction would corrupt the comparison).
//   P5. Salt: 32 random bytes reduced mod the field prime (parity with
//       reference implementations; cosmetic — any field element proves).
//   P6. Every generated proof is verified locally against the bundled
//       verification key before being returned; a proof that fails local
//       verification is dropped and logged as proof=VERIFY-FAILED so the
//       Vercel log line distinguishes "attached" from "attached but bad".
//       Disable with AGENT_SELF_VERIFY=0.
//   P7. warmUpProveAssets() export so the HTTP layer can pre-load the
//       proving assets on handshake/health pings (instance warm-up).
//
// === MINUS6-FIX 2026-11-19 (NOT DEPLOYED — review copy) ===
// Root cause of the recurring -6 (rounds 05/06/07): P2's durable store
// is env-gated and no KV was ever provisioned in production, so reuse
// detection silently ran on per-instance memory only and every cold
// instance APPROVED the round's PROOF_REUSED trap (all fields valid).
//   F1. File-backed durable tier (GK_STORE_FILE) between KV-REST and
//       memory: seen-set + response cache persist across processes /
//       cold starts wherever a filesystem is shared.
//   F2. The active store backend is logged once (gkstore backend=...),
//       with a loud warning when memory-only — the inert configuration
//       is no longer silent.
// On Vercel, cross-instance durability still requires the KV tier
// (provision Upstash via Vercel Storage so KV_REST_API_* appear).
//
// Implements the agent interface documented at https://agentgames.zkverify.io/build
// and https://agentgames.zkverify.io/events/proof-gatekeeper :
//   - Incoming: JSON POST envelope, HMAC-SHA256 signature in the
//     `x-agent-games-signature` header, verified against the RAW body before parsing.
//   - Outgoing: { decision: "APPROVE"|"REJECT", reason_code, proof_tx, proof, public_signals }
//     signed with `x-agent-games-signature` over the raw response body.
//   - The Groth16 proof is generated locally with snarkjs from the bundled
//     gatekeeper circuit (circuits/gatekeeper.wasm + gatekeeper_final.zkey).

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import jsSha3 from 'js-sha3';

const { keccak256 } = jsSha3;

// BN254 (bn128) scalar field prime.
const FIELD_PRIME =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

function wasmPath() {
  return path.join(process.cwd(), 'circuits', 'gatekeeper.wasm');
}
function zkeyPath() {
  return path.join(process.cwd(), 'circuits', 'gatekeeper_final.zkey');
}
function vkeyPath() {
  return path.join(process.cwd(), 'circuits', 'verification_key.json');
}

// ---------------------------------------------------------------------------
// HMAC secret handling
// ---------------------------------------------------------------------------

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
  return hmacSha256(Buffer.from(rawBodyString, 'utf8'), secret).toString('hex');
}

// ---------------------------------------------------------------------------
// Field conversions
// ---------------------------------------------------------------------------

export function toFieldDecimal(value) {
  if (typeof value === 'bigint') return value.toString();
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Error('non-finite number');
    // [AUDIT-PATCH P3] was: silent truncation of fractional numbers, which
    // could flip a boundary decision (amount 1000.7 -> 1000 -> APPROVE).
    if (!Number.isInteger(value)) throw new Error('non-integer number');
    return BigInt(value).toString();
  }
  if (typeof value === 'string') {
    const v = value.trim();
    // [AUDIT-PATCH P3] accept 0x and 0X prefixes.
    if (/^0[xX][0-9a-fA-F]+$/.test(v)) return BigInt(v).toString();
    if (/^[0-9]+$/.test(v)) return BigInt(v).toString();
    // [AUDIT-PATCH P3] bare hex (no prefix) for address/VK-style fields:
    // unambiguous when it contains a-f letters and is at least an
    // address-length 40 hex chars (pure-digit strings stay decimal).
    if (/^[0-9a-fA-F]+$/.test(v) && /[a-fA-F]/.test(v) && v.length >= 40) {
      return BigInt('0x' + v).toString();
    }
    throw new Error(`cannot convert to field element: ${value}`);
  }
  throw new Error(`unsupported field value type: ${typeof value}`);
}

function toBig(value) {
  return BigInt(toFieldDecimal(value));
}

// The platform re-derives the circuit taskId as keccak256(utf8(task_id))
// mod the BN254 prime (documented publicly by fellow participants after
// Round 2). Numeric ids pass through unchanged.
export function taskIdToField(taskId) {
  const s = String(taskId ?? '');
  if (/^[0-9]+$/.test(s)) return BigInt(s).toString();
  const digest = keccak256(s);
  return (BigInt('0x' + digest) % FIELD_PRIME).toString();
}

// Circuit artifacts + snarkjs are loaded once per warm instance and reused
// across tasks (buffers instead of per-request disk reads) to keep the
// proving path fast.
let proveAssetsPromise = null;
function loadProveAssets() {
  if (!proveAssetsPromise) {
    proveAssetsPromise = (async () => {
      const { groth16 } = await import('snarkjs');
      const wasm = fs.readFileSync(wasmPath());
      const zkey = fs.readFileSync(zkeyPath());
      // [AUDIT-PATCH P6] verification key for the local self-verify step;
      // optional — if the file is ever missing, self-verify is skipped.
      let vkey = null;
      try {
        vkey = JSON.parse(fs.readFileSync(vkeyPath(), 'utf8'));
      } catch {
        vkey = null;
      }
      return { groth16, wasm, zkey, vkey };
    })();
  }
  return proveAssetsPromise;
}

// [AUDIT-PATCH P7] Fire-and-forget warm-up, called by the HTTP layer on
// handshake/health requests so a following task POST on the same warm
// instance skips the snarkjs import + artifact reads.
export function warmUpProveAssets() {
  loadProveAssets().catch(() => {});
}

function randomSalt() {
  // [AUDIT-PATCH P5] 32 random bytes (parity with reference agents),
  // reduced mod the field prime so the value is always a canonical
  // field element.
  return (BigInt('0x' + crypto.randomBytes(32).toString('hex')) % FIELD_PRIME).toString();
}

// ---------------------------------------------------------------------------
// [AUDIT-PATCH P2] Optional durable store (Upstash Redis / Vercel KV REST).
// Fail-open everywhere: any error or timeout falls back to the in-memory
// maps, and a store outage can never block or break a task response.
// ---------------------------------------------------------------------------

function storeConfig() {
  const url = process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL;
  const token = process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN;
  if (!url || !token) return null;
  return { url: url.replace(/\/$/, ''), token };
}

// [MINUS6-FIX F1/F2] Backend selection is explicit and logged once:
// KV-REST (cross-instance on Vercel) > file (cross-process wherever a
// filesystem is shared) > memory-only (per-instance; reuse detection
// cannot survive a cold start — warned loudly, never silent again).
let storeBackendLogged = false;
function storeBackend() {
  if (storeConfig()) return 'kv-rest';
  if (process.env.GK_STORE_FILE) return 'file';
  return 'memory';
}
function logStoreBackend() {
  if (storeBackendLogged) return;
  storeBackendLogged = true;
  const backend = storeBackend();
  if (backend === 'memory') {
    console.log(
      'gkstore backend=memory-only WARNING: no durable store configured ' +
        '(KV_REST_API_URL/KV_REST_API_TOKEN or GK_STORE_FILE); PROOF_REUSED ' +
        'detection is limited to this instance and cold starts will miss reuses',
    );
  } else {
    console.log(`gkstore backend=${backend}`);
  }
}

// [MINUS6-FIX F1] File tier. The whole store is one small JSON object
// ({ key: { v, exp } }); every command re-reads the file and every SET
// rewrites it via temp-file + rename, so sequential processes (the
// platform delivers one task at a time per agent) always see each
// other's writes. Any fs error fails open to the L1 maps, like KV.
function fileStoreRead(file) {
  try {
    const parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
    return parsed && typeof parsed === 'object' ? parsed : {};
  } catch {
    return {};
  }
}
function fileStoreCommand(command) {
  const file = process.env.GK_STORE_FILE;
  const [op, key, value] = command;
  const data = fileStoreRead(file);
  const now = Math.floor(Date.now() / 1000);
  const live = (entry) => entry && (entry.exp == null || entry.exp > now);
  if (op === 'GET') {
    const entry = data[key];
    return live(entry) ? entry.v : null;
  }
  if (op === 'SET') {
    const nx = command.includes('NX');
    if (nx && live(data[key])) return null;
    const exIdx = command.indexOf('EX');
    const exp = exIdx >= 0 ? now + Number(command[exIdx + 1]) : null;
    data[key] = { v: String(value), exp };
    try {
      const tmp = `${file}.tmp-${process.pid}`;
      fs.writeFileSync(tmp, JSON.stringify(data));
      fs.renameSync(tmp, file);
    } catch {
      return null;
    }
    return 'OK';
  }
  return null;
}

async function storeCommand(command, timeoutMs = 1200) {
  logStoreBackend();
  if (storeBackend() === 'file') {
    try {
      return fileStoreCommand(command);
    } catch {
      return null;
    }
  }
  const cfg = storeConfig();
  if (!cfg) return null;
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(cfg.url, {
      method: 'POST',
      headers: {
        authorization: `Bearer ${cfg.token}`,
        'content-type': 'application/json',
      },
      body: JSON.stringify(command),
      signal: ctrl.signal,
    });
    if (!res.ok) return null;
    const json = await res.json();
    return json?.result ?? null;
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

const SEEN_TTL_SECONDS = 864000; // 10 days — covers the rest of the event
const RESP_TTL_SECONDS = 172800; // 2 days — retries arrive within minutes

const seenProofs = new Map(); // proof_tx -> task_id (L1, in-memory)
const responseCache = new Map(); // task_id -> raw response string (L1)

function cacheSet(map, key, value, cap = 500) {
  if (map.size >= cap) map.delete(map.keys().next().value);
  map.set(key, value);
}

async function lookupReused(proofTx, taskId) {
  const key = String(proofTx);
  const tid = String(taskId);
  if (seenProofs.has(key)) return seenProofs.get(key) !== tid;
  const stored = await storeCommand(['GET', `gkseen:${key}`]);
  if (stored != null) {
    seenProofs.set(key, String(stored));
    return String(stored) !== tid;
  }
  return false;
}

async function recordSeen(proofTx, taskId) {
  const key = String(proofTx);
  seenProofs.set(key, String(taskId));
  // NX: never overwrite the first task that used this proof reference.
  await storeCommand(['SET', `gkseen:${key}`, String(taskId), 'NX', 'EX', SEEN_TTL_SECONDS]);
}

async function lookupCachedResponse(taskId) {
  const key = String(taskId);
  if (responseCache.has(key)) return responseCache.get(key);
  const stored = await storeCommand(['GET', `gkresp:${key}`]);
  if (stored != null) {
    cacheSet(responseCache, key, String(stored));
    return String(stored);
  }
  return null;
}

async function recordResponse(taskId, rawResponse) {
  const key = String(taskId);
  cacheSet(responseCache, key, rawResponse);
  await storeCommand(['SET', `gkresp:${key}`, rawResponse, 'EX', RESP_TTL_SECONDS]);
}

// ---------------------------------------------------------------------------
// Decision logic — mirrors the trap encyclopedia on the track page.
// Circuit semantics (feasibility-verified): decision = AND(all checks).
// ---------------------------------------------------------------------------

// [AUDIT-PATCH P1] precedence: VK -> PROOF_REUSED -> THRESHOLD ->
// EXPIRED -> RECIPIENT -> AMOUNT (reference-flow order).
export function evaluateTask(input, isReused = false) {
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
  if (isReused) return { decision: 0, reason_code: 'PROOF_REUSED' };
  if (publicBalance < minimum) return { decision: 0, reason_code: 'THRESHOLD_MISMATCH' };
  if (!(currentBlock < expiryBlock)) return { decision: 0, reason_code: 'EXPIRED_CONDITION' };
  if (recipient !== conditionRecipient)
    return { decision: 0, reason_code: 'RECIPIENT_MISMATCH' };
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

// [AUDIT-PATCH P4] The old guard skipped proving whenever any compared
// field reached 2^70. Measurements against the real circuit (2026-11-16)
// show the actual limits are difference-based and field-specific (the
// balance/minimum comparison only proves when |balance - minimum| fits
// roughly 32 bits; block and amount comparisons tolerate far larger
// absolute values when their differences are small). A witness failure
// is fast (~100 ms) and caught below, so an absolute-value guard only
// risks skipping proofs the circuit could have produced. Proving is now
// skipped only when a compared field is >= the field prime, where the
// witness calculator's modular reduction would corrupt the comparison.
function comparedValuesFitCircuit(input) {
  const fields = [
    input.minimum,
    input.public_balance ?? input.publicBalance,
    input.expiry_block ?? input.expiryBlock,
    input.current_block ?? input.currentBlock,
    input.amount,
    input.max_transfer ?? input.maxTransfer,
  ];
  try {
    return fields.every((v) => toBig(v) >= 0n && toBig(v) < FIELD_PRIME);
  } catch {
    return false;
  }
}

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

  // [AUDIT-PATCH P2] Idempotent retries: task IDs are idempotency keys —
  // a retried task gets the byte-identical earlier response (same proof,
  // same salt commitment) instead of a freshly generated proof.
  if (taskId != null) {
    const cached = await lookupCachedResponse(taskId);
    if (cached != null) {
      console.log(`gatekeeper task=${taskId} cached-response replay`);
      return {
        status: 200,
        body: JSON.parse(cached),
        rawResponse: cached,
        responseSignature: signBody(cached, secret),
      };
    }
  }

  // [AUDIT-PATCH P1/P2] Reuse is decided before the field traps (after
  // the VK check inside evaluateTask) and now survives cold starts when
  // the durable store is configured.
  const isReused = proofTx ? await lookupReused(proofTx, taskId) : false;
  const { decision, reason_code } = evaluateTask(input, isReused);

  const body = {
    task_id: taskId,
    decision: decision === 1 ? 'APPROVE' : 'REJECT',
    reason_code,
    proof_tx: proofTx,
  };

  // Generate the Groth16 proof of our decision. Skipped for INVALID_INPUT
  // (nothing meaningful to prove) and for PROOF_REUSED (the track page:
  // reused tasks "have no proof to submit" — and for an otherwise-valid
  // task a decision=0 proof cannot exist, the circuit asserts decision =
  // AND(checks)). If proving fails for any other reason, the decision
  // still goes out without a proof: a bare decision scores as a response,
  // a thrown 500 scores as silence.
  if (
    reason_code !== 'INVALID_INPUT' &&
    reason_code !== 'PROOF_REUSED' &&
    comparedValuesFitCircuit(input)
  ) {
    const proveStart = Date.now();
    try {
      const circuitInputs = buildCircuitInputs(envelope, input, decision);
      const { groth16, wasm, zkey, vkey } = await loadProveAssets();
      const { proof, publicSignals } = await groth16.fullProve(circuitInputs, wasm, zkey);
      // [AUDIT-PATCH P6] Local self-verify before returning.
      let verified = null;
      if (vkey && process.env.AGENT_SELF_VERIFY !== '0') {
        verified = await groth16.verify(vkey, publicSignals, proof);
      }
      if (verified === false) {
        console.log(
          `gatekeeper task=${taskId} reason=${reason_code} proof=VERIFY-FAILED prove_ms=${Date.now() - proveStart} taskField=${publicSignals?.[12]}`,
        );
      } else {
        body.proof = proof;
        body.public_signals = publicSignals;
        console.log(
          `gatekeeper task=${taskId} reason=${reason_code} proof=attached prove_ms=${Date.now() - proveStart} taskField=${publicSignals?.[12]}`,
        );
      }
    } catch (err) {
      console.log(
        `gatekeeper task=${taskId} reason=${reason_code} proof=FAILED prove_ms=${Date.now() - proveStart} err=${String(err?.message ?? err)}`,
      );
      // Decision stands; the response simply carries no proof.
    }
  } else {
    console.log(
      `gatekeeper task=${taskId} reason=${reason_code} proof=skipped (unparsable, reused, or out of circuit range)`,
    );
  }

  const out = respond(200, body, secret);
  if (proofTx && !isReused) await recordSeen(proofTx, taskId);
  if (taskId != null) await recordResponse(taskId, out.rawResponse);
  return out;
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
