// POST /api/task — Proof Gatekeeper task endpoint (also served at /task via rewrite).
// The raw body is required for HMAC verification, so Vercel's body parser is off.
import { handleTask, getSecret, signBody } from '../lib/agent.js';

export const config = {
  api: { bodyParser: false },
};

// Hard response deadline on the platform is 60 seconds (Build guide §02).
export const maxDuration = 60;

function readRawBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

// Protocol-v1 handshake (preflight diagnostic, 2026-11-15): the platform
// probes the registered endpoint and expects a signed JSON body
// {"ok":true,"protocolVersion":"v1"} with a valid x-agent-games-signature
// header (HMAC over the raw response body). Probes arrive as GET requests
// or as POSTs that do not carry a task envelope, so both are answered with
// the handshake; genuine task envelopes keep the strict signed flow below.
function sendHandshake(res) {
  const secret = getSecret();
  if (!secret) {
    res.status(500).json({ error: 'AGENT_HMAC_SECRET is not configured' });
    return;
  }
  const raw = JSON.stringify({ ok: true, protocolVersion: 'v1' });
  res.status(200);
  res.setHeader('content-type', 'application/json');
  res.setHeader('x-agent-games-signature', signBody(raw, secret));
  res.send(raw);
}

// A request counts as a task envelope only if it carries actual task inputs
// (mirrors the envelope shapes handleTask understands). Anything else that
// reaches this endpoint — empty bodies, ping/preflight probes — is not a
// scored task and gets the handshake instead of a signature rejection.
function isTaskEnvelope(rawBody) {
  if (!rawBody || rawBody.length === 0) return false;
  let parsed;
  try {
    parsed = JSON.parse(rawBody.toString('utf8'));
  } catch {
    return false;
  }
  if (!parsed || typeof parsed !== 'object') return false;
  if (parsed.type === 'ping' || parsed.type === 'preflight' || parsed.event === 'ping') {
    return false;
  }
  const input = parsed.input ?? parsed;
  if (!input || typeof input !== 'object') return false;
  return (
    input.proof_tx !== undefined ||
    input.proofTx !== undefined ||
    input.registered_vk !== undefined ||
    input.registeredVk !== undefined ||
    input.amount !== undefined ||
    input.minimum !== undefined
  );
}

export default async function handler(req, res) {
  if (req.method === 'GET' || req.method === 'HEAD') {
    sendHandshake(res);
    return;
  }
  if (req.method !== 'POST') {
    res.status(405).json({ error: 'method not allowed' });
    return;
  }
  try {
    const rawBody = await readRawBody(req);
    if (!isTaskEnvelope(rawBody)) {
      sendHandshake(res);
      return;
    }
    const signature = req.headers['x-agent-games-signature'];
    const out = await handleTask(rawBody, signature);
    res.status(out.status);
    res.setHeader('content-type', 'application/json');
    if (out.responseSignature) {
      res.setHeader('x-agent-games-signature', out.responseSignature);
    }
    res.send(out.rawResponse);
  } catch (err) {
    // Fail closed: an explicit 500 scores better than a hung connection,
    // and nothing is ever approved on error.
    res.status(500).json({ error: 'internal error', detail: String(err?.message ?? err) });
  }
}
