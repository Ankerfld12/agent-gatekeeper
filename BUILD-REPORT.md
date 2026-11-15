# Build Report — Proof Gatekeeper Agent (Vercel)

Date: 2026-11-15. Scope: local build + self-test only. Nothing was deployed,
registered, signed, or submitted.

## 1. What the official pages actually document vs. what was assumed

### Documented (read 2026-11-15 from /build, /events/proof-gatekeeper, /rules)

| Item | Source | How it is implemented |
|---|---|---|
| Task envelope: `{type: "agent-games.proof-gatekeeper.v1", task_id, mode, issued_at, deadline_at, input{registered_vk, proof_vk, minimum, public_balance, expiry_block, current_block, recipient, condition_recipient, amount, max_transfer, proof_tx}}` | Track page, "Sample task payload" | Parsed exactly with these snake_case names (camelCase accepted as fallback). |
| Response shape: `{decision: "REJECT", reason_code: "VK_SUBSTITUTION", proof_tx: "0x…"}` — decision is the string `"APPROVE"`/`"REJECT"` | Track page, "Expected response shape" | Returned as documented; `task_id`, `proof`, `public_signals` added (see assumptions). |
| Reason codes = trap names: VALID_CONDITION (approve), VK_SUBSTITUTION, THRESHOLD_MISMATCH, PROOF_REUSED, EXPIRED_CONDITION, RECIPIENT_MISMATCH, AMOUNT_OVERFLOW | Track page, "Trap encyclopedia" | Decision logic returns exactly these codes. |
| Verify the HMAC signature against the **raw body before parsing** | Build guide §02 | Raw body read first, HMAC verified, only then JSON.parse. |
| Header name `x-agent-games-signature`; **responses are also signed** with it over the raw response body | Rules §1.3; Build guide §04 | Verified inbound; outbound response body signed and header set. |
| Secret: platform-generated 32-byte value, shown exactly once at registration, rotatable ("Rotate Secret"); never a local placeholder | Rules §1.3; Build guide §04 | Read from env `AGENT_HMAC_SECRET`; no default/fallback — unconfigured ⇒ HTTP 500, nothing processed. |
| Hard 60-second response deadline; HTTPS-only public endpoint; passing health check required | Build guide §02; track page entry requirements | `maxDuration: 60` on the task function; health endpoint provided. |
| Circuits are Groth16/BN128 (Circom 2.x); generate proofs locally with snarkjs and **include the proof in the response** | Build guide §02.5 | snarkjs `groth16.fullProve` with bundled gatekeeper wasm/zkey. |
| Task IDs are idempotency keys (platform may retry) | Rules §1.2 | Same-task retries re-answer with the same decision; reuse detection only fires for a *different* task_id reusing a proof_tx. |
| "PROOF_REUSED tasks have no proof to submit and are excluded" (from reliability bonus) | Track page, score model | PROOF_REUSED branch returns decision + reason_code with **no** proof attached. |
| Decision = approve only when VK matches, balance ≥ minimum, recipient matches, not expired, amount ≤ cap (circuit enforces `decision = AND(checks)` — feasibility-verified) | Track page checklist + feasibility.md | `evaluateTask()` implements exactly these five checks. |

### Assumed (NOT documented — all marked TODO-VERIFY-AFTER-REGISTRATION in code/README)

1. **Health-check path & payload.** No path is published. Chosen: `GET /health` and
   `GET /api/health` → `{"ok":true}`.
2. **Signature encoding.** Header is named, encoding is not. Inbound accepts hex,
   base64, or `sha256=`-prefixed forms (timing-safe compare). Outbound signs hex.
3. **Secret encoding.** Assumed the env string is used as UTF-8 HMAC key bytes.
   Escape hatch: `AGENT_HMAC_SECRET_IS_HEX=1` interprets it as hex bytes.
4. **taskId field encoding.** Envelope `task_id` is a string (`"gk_24_9d1"`); the
   circuit needs a field element and no encoding is published. Chosen: numeric ids
   pass through; other strings are SHA-256-hashed and reduced mod the BN254 prime.
   **Highest-risk assumption** — if the platform re-derives public inputs its own
   way, our proofs fail their verification. Check with a practice task first.
5. **Proof field names in the response.** The documented response example shows no
   proof field, yet the build guide says to include the proof. Chosen: `proof`
   (snarkjs proof object) + `public_signals` (array of decimal strings), plus a
   `task_id` echo. Extra fields are normally ignored by strict-but-sane parsers.
6. **Reason-code precedence** when several traps coincide: VK_SUBSTITUTION →
   THRESHOLD_MISMATCH → RECIPIENT_MISMATCH → EXPIRED_CONDITION → AMOUNT_OVERFLOW.
7. **`INVALID_INPUT` reason code** for unparsable numeric fields (invented;
   fail-closed REJECT). Undocumented situation.
8. **No zkVerify/Kurier submission.** Build guide §03 and checklist step 02
   describe confirming the platform's proof on-chain via zkVerifyJS/Kurier
   (needs a Kurier mainnet API key). Not implemented — the agent decides purely
   from envelope fields and returns its own Groth16 proof, per the build spec
   given for this project. Revisit after registration if practice tasks demand a
   `proofReference`/finalized attestation instead of a raw proof.

## 2. Self-test results (local, 2026-11-15)

Harness: `test/local-test.mjs` — plain Node HTTP server mounting the same
`lib/agent.js` logic as the Vercel functions; sample envelopes mirror the
documented shape using the feasibility-verified values. Proofs checked with
`snarkjs groth16 verify` against `circuits/verification_key.json`.

| # | Check | Result | Time |
|---|---|---|---|
| 1 | GET /health → `{"ok":true}` | PASS | 57.6 ms |
| 2 | POST /task valid condition → HTTP 200 | PASS | 2 448 ms (cold: includes snarkjs load + first prove) |
| 3 | → decision `APPROVE`, reason `VALID_CONDITION` | PASS | — |
| 4 | → returned proof passes `groth16 verify` | PASS | — |
| 5 | → response carries valid `x-agent-games-signature` | PASS | — |
| 6 | POST /task amount 1500 > cap → `REJECT` / `AMOUNT_OVERFLOW` | PASS | 712 ms (warm) |
| 7 | → trap proof (decision=0) passes `groth16 verify` | PASS | — |
| 8 | POST /task substituted proof_vk → `REJECT` / `VK_SUBSTITUTION` | PASS | 689 ms (warm) |
| 9 | → trap proof passes `groth16 verify` | PASS | — |
| 10 | POST /task wrong HMAC → HTTP 401, no proving work | PASS | 6 ms |

**10/10 passed.** Whole suite wall time ≈ 5.3 s.

Adapter smoke test (the actual `api/health.js` / `api/task.js` Vercel handlers
driven with mock req/res): health → `200 {"ok":true}`; task → `200`, decision
`APPROVE` / `VALID_CONDITION`, proof present, response-signature header present,
**2 207 ms** cold. (The test process then had to be killed: snarkjs/ffjavascript
worker threads keep a bare Node process alive after work completes — harmless in
Vercel's function model, noted for local debugging.)

Reference point from feasibility: CLI `fullProve` ≈ 2.65 s including Node
startup. All measured paths are far inside the 60 s deadline.

## 3. File list (~/workspace/agentgames/vercel-app/)

| File | Purpose |
|---|---|
| `api/health.js` | GET /api/health → `{"ok":true}` (dependency-free). |
| `api/task.js` | POST /api/task adapter: raw-body read, `maxDuration = 60`, delegates to lib. |
| `lib/agent.js` | Core logic: HMAC verify/sign, field conversion, decision + reason codes, PROOF_REUSED seen-set, snarkjs proving. |
| `circuits/gatekeeper.wasm` | Circuit wasm (1.7 MB, copied from the verified feasibility set). |
| `circuits/gatekeeper_final.zkey` | Proving key (304 KB). |
| `circuits/verification_key.json` | VK used by the local self-test to verify proofs. |
| `vercel.json` | Rewrites `/health`→`/api/health`, `/task`→`/api/task`; task function: maxDuration 60, memory 1024, `includeFiles: circuits/**`. |
| `package.json` / `package-lock.json` | Node ≥ 18, ESM, dependency `snarkjs ^0.7.6`; script `test:local`. |
| `test/local-test.mjs` | End-to-end self-test described above. |
| `README.md` | Indonesian click-by-click deploy guide for the owner + post-registration TODO list. |
| `.gitignore` | node_modules, .vercel, env files. |

## 4. Remaining risks

- **Cold start:** first invocation loads snarkjs + 1.7 MB wasm. Local cold task
  ≈ 2.2–2.5 s end-to-end; warm ≈ 0.7 s. Even a several-times-slower Vercel cold
  start stays far under 60 s, but the first practice task should confirm this.
- **Vercel plan limits:** `maxDuration: 60` matches the platform deadline. On the
  Hobby plan 60 s is the maximum configurable function duration, so the setting is
  valid there; if a deploy ever silently caps duration lower, tasks would time
  out platform-side (−2 each) — verify in the Vercel dashboard after first deploy.
- **Bundle inclusion:** the function reads `circuits/*` via `process.cwd()`.
  `includeFiles: circuits/**` is set, but the first deployed practice task is the
  real proof that Vercel shipped the files; a 500 mentioning ENOENT/gatekeeper.wasm
  would mean fixing paths (fallback: resolve relative to the function file).
- **taskId encoding & proof field names** (assumptions 4–5) can only be settled by
  a real practice task after registration.
- **PROOF_REUSED memory:** in-memory seen-set resets on cold start; a reused-proof
  trap arriving at a fresh instance would be judged on its other fields (and
  likely still rejected only if another check fails — otherwise wrongly approved,
  −6). Durable storage (Vercel KV/Upstash) is the fix if practice shows this trap
  matters; ~11% of tasks per the track page, so treat this as a real TODO.
- **Idempotent retries:** a retried task_id gets a fresh proof (new random salt)
  with the same decision. If the platform expects byte-identical retry responses,
  add response caching keyed by task_id.
- **Uptime:** scored rounds run 16:00–02:00 IST daily until 21 Nov; Vercel
  serverless does not sleep, but the project must not be paused/deleted, and
  Hobby-plan usage limits (invocations/bandwidth) should be watched — task volume
  is tiny (≤ 8 scored + ≤ 10 practice/hour), so this is low risk.
