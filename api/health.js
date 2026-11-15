// GET /api/health — platform health check (also served at /health via rewrite).
// Deliberately dependency-free so health checks stay fast even on cold start.
export default function handler(req, res) {
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    res.status(405).json({ error: 'method not allowed' });
    return;
  }
  res.status(200).json({ ok: true });
}
