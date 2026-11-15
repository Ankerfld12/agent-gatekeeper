// POST /api/task — Proof Gatekeeper task endpoint (also served at /task via rewrite).
// The raw body is required for HMAC verification, so Vercel's body parser is off.
import { handleTask } from '../lib/agent.js';

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

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    res.status(405).json({ error: 'method not allowed' });
    return;
  }
  try {
    const rawBody = await readRawBody(req);
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
