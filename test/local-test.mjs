// Local end-to-end self-test for the Proof Gatekeeper agent.
//
// Starts a plain Node HTTP server that mounts the SAME logic used by the
// Vercel functions (lib/agent.js handleTask + the health response), then:
//   1. GET  /health                       -> { ok: true }
//   2. POST /task  (valid condition)      -> APPROVE + proof that verifies
//   3. POST /task  (amount over the cap)  -> REJECT AMOUNT_OVERFLOW + proof verifies
//   4. POST /task  (VK substitution)      -> REJECT VK_SUBSTITUTION + proof verifies
//   5. POST /task  (bad HMAC signature)   -> 401
// Proofs are checked with snarkjs groth16 verify against circuits/verification_key.json.
//
// Run:  npm run test:local

import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

process.env.AGENT_HMAC_SECRET = 'self-test-secret-do-not-use-in-production';
const SECRET = process.env.AGENT_HMAC_SECRET;

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
process.chdir(root); // lib/agent.js resolves circuits/ from process.cwd()

const { handleTask, hmacSha256 } = await import('../lib/agent.js');
const { groth16 } = await import('snarkjs');
const vkey = JSON.parse(
  fs.readFileSync(path.join(root, 'circuits', 'verification_key.json'), 'utf8'),
);

// --- tiny server mounting the same handlers as api/*.js ---------------------
const server = http.createServer(async (req, res) => {
  if (req.url === '/health' && req.method === 'GET') {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ ok: true }));
    return;
  }
  if (req.url === '/task' && req.method === 'POST') {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', async () => {
      const out = await handleTask(
        Buffer.concat(chunks),
        req.headers['x-agent-games-signature'],
      );
      const headers = { 'content-type': 'application/json' };
      if (out.responseSignature)
        headers['x-agent-games-signature'] = out.responseSignature;
      res.writeHead(out.status, headers);
      res.end(out.rawResponse);
    });
    return;
  }
  res.writeHead(404).end();
});
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const base = `http://127.0.0.1:${server.address().port}`;

// --- sample envelope, mirroring the documented shape on the track page -----
// Values are the feasibility-verified ones (~/workspace/agentgames/input.json),
// re-encoded the way the platform sends them (hex strings / numbers).
const VK_HEX =
  '0x' +
  BigInt(
    '48612629870452471351995307734854562318858385272285416761371572079729769805744',
  ).toString(16);
const RECIPIENT_HEX =
  '0x' + BigInt('103929005307927756724354605802047639613112342136').toString(16);

function makeEnvelope(overrides = {}, inputOverrides = {}) {
  return {
    type: 'agent-games.proof-gatekeeper.v1',
    task_id: 'gk_selftest_1',
    mode: 'practice',
    issued_at: new Date().toISOString(),
    deadline_at: new Date(Date.now() + 60_000).toISOString(),
    input: {
      registered_vk: VK_HEX,
      proof_vk: VK_HEX,
      minimum: '1000',
      public_balance: '1460',
      expiry_block: 8430000,
      current_block: 8420000,
      recipient: RECIPIENT_HEX,
      condition_recipient: RECIPIENT_HEX,
      amount: '500',
      max_transfer: '1000',
      proof_tx: '0xselftestproof00000000000000000000000000000001',
      ...inputOverrides,
    },
    ...overrides,
  };
}

async function postTask(envelope, { sign = true } = {}) {
  const raw = JSON.stringify(envelope);
  const headers = { 'content-type': 'application/json' };
  if (sign) {
    headers['x-agent-games-signature'] = hmacSha256(
      Buffer.from(raw, 'utf8'),
      Buffer.from(SECRET, 'utf8'),
    ).toString('hex');
  } else {
    headers['x-agent-games-signature'] = 'deadbeef'.repeat(8);
  }
  const t0 = performance.now();
  const res = await fetch(`${base}/task`, { method: 'POST', headers, body: raw });
  const text = await res.text();
  const ms = performance.now() - t0;
  let json = null;
  try {
    json = JSON.parse(text);
  } catch {
    /* leave null */
  }
  return { res, text, json, ms };
}

async function proofVerifies(json) {
  if (!json?.proof || !json?.public_signals) return false;
  return groth16.verify(vkey, json.public_signals, json.proof);
}

const results = [];
function check(name, cond, extra = '') {
  results.push({ name, pass: !!cond, extra });
  console.log(`${cond ? 'PASS' : 'FAIL'}  ${name}${extra ? ` — ${extra}` : ''}`);
}

// 1. health
{
  const t0 = performance.now();
  const res = await fetch(`${base}/health`);
  const json = await res.json();
  const ms = performance.now() - t0;
  check('GET /health -> {ok:true}', res.status === 200 && json.ok === true, `${ms.toFixed(1)} ms`);
}

// 2. valid condition -> APPROVE + verifying proof
{
  const { res, json, ms, text } = await postTask(makeEnvelope());
  check('POST /task valid -> 200', res.status === 200, `${ms.toFixed(0)} ms total`);
  check(
    'decision APPROVE / VALID_CONDITION',
    json?.decision === 'APPROVE' && json?.reason_code === 'VALID_CONDITION',
  );
  check('proof verifies (groth16 verify)', await proofVerifies(json));
  const sig = res.headers.get('x-agent-games-signature');
  const expected = hmacSha256(
    Buffer.from(text, 'utf8'),
    Buffer.from(SECRET, 'utf8'),
  ).toString('hex');
  check('response is HMAC-signed', sig === expected);
}

// 3. trap: amount over cap -> REJECT AMOUNT_OVERFLOW + verifying proof
{
  const env = makeEnvelope(
    { task_id: 'gk_selftest_2' },
    { amount: '1500', proof_tx: '0xselftestproof00000000000000000000000000000002' },
  );
  const { res, json, ms } = await postTask(env);
  check(
    'POST /task amount-overflow -> REJECT AMOUNT_OVERFLOW',
    res.status === 200 &&
      json?.decision === 'REJECT' &&
      json?.reason_code === 'AMOUNT_OVERFLOW',
    `${ms.toFixed(0)} ms total`,
  );
  check('trap proof verifies (decision=0 is provable)', await proofVerifies(json));
}

// 4. trap: VK substitution -> REJECT VK_SUBSTITUTION + verifying proof
{
  const env = makeEnvelope(
    { task_id: 'gk_selftest_3' },
    {
      proof_vk: '0x' + '11'.repeat(32),
      proof_tx: '0xselftestproof00000000000000000000000000000003',
    },
  );
  const { res, json, ms } = await postTask(env);
  check(
    'POST /task vk-substitution -> REJECT VK_SUBSTITUTION',
    res.status === 200 &&
      json?.decision === 'REJECT' &&
      json?.reason_code === 'VK_SUBSTITUTION',
    `${ms.toFixed(0)} ms total`,
  );
  check('vk-trap proof verifies', await proofVerifies(json));
}

// 5. bad signature -> 401, no proof work done
{
  const { res, ms } = await postTask(makeEnvelope(), { sign: false });
  check('POST /task bad signature -> 401', res.status === 401, `${ms.toFixed(0)} ms`);
}

server.close();
const failed = results.filter((r) => !r.pass);
console.log(
  `\n${results.length - failed.length}/${results.length} checks passed` +
    (failed.length ? ` — FAILURES: ${failed.map((f) => f.name).join('; ')}` : ''),
);
process.exit(failed.length ? 1 : 0);
