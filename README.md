# landing-api-worker

Cloudflare Worker that reverse-proxies the landing page's frontend to the
`landing-page-backend` AWS Lambda Function URL, signing every request with
AWS Signature V4 (`service: lambda`) using long-lived IAM credentials stored
as Worker secrets.

This lets the Lambda Function URL be locked down with
`AuthType: AWS_IAM` (instead of `NONE`) so only this worker (and whoever else
holds those credentials) can invoke it, while the browser keeps talking to a
plain public HTTPS endpoint with no AWS knowledge.

```
landing-api-worker/
├── package.json
├── wrangler.toml
└── src/
    └── index.js
```

## How it works

- `POST /`, `POST /schedule-meeting`, and `POST /wake-up` are the only routes
  proxied, matching the endpoints in `landing-page-backend/src/main.py`.
- Every proxied request is signed with `@aws-sdk/signature-v4` +
  `@aws-crypto/sha256-js` (pure-JS SHA-256, no Node crypto needed — works on
  Workers' V8 isolate runtime) before being forwarded to `LAMBDA_URL`. The
  signed headers also include `x-real-ip` (from `CF-Connecting-IP`) — since
  it's part of the SigV4 signature, only this Worker can set it truthfully,
  so the Lambda can trust it as the real caller IP for its own per-user rate
  limiting (it otherwise has no visibility into the original client at all).
- The chat endpoint's streamed SSE response (`AWS_LWA_INVOKE_MODE=response_stream`)
  is passed straight through — `upstreamResponse.body` is forwarded byte-for-byte,
  it is never buffered here.
- CORS is enforced in the worker (checked against `ALLOWED_ORIGINS`), since
  once the Lambda sits behind IAM auth its own `CORSMiddleware` no longer sees
  the real browser `Origin`.
- `POST /schedule-meeting` additionally enforces a 24h per-caller cooldown
  using Workers KV (free tier): the caller's IP + User-Agent are hashed
  (SHA-256, via the runtime's native Web Crypto — never stored in plaintext)
  into a KV key. If that key exists, the request is rejected with `429` and a
  `Retry-After` header *before* it ever reaches the Lambda. Otherwise the
  request is proxied as usual, its (small, non-streamed) JSON body is read to
  check `status`, and the key is written with `expirationTtl: 86400` unless
  the outcome was the hard failure `"the meeting is not scheduled"` (see
  `MeetingScheduledStatus` in `landing-page-backend/src/agent_tools/tools.py`)
  — i.e. it still blocks on the partial-success case ("saved but email
  failed"). KV's TTL handles expiry automatically, no cleanup job needed.
  This is separate from — and in addition to — the dashboard Rate Limiting
  Rule already limiting burst frequency (4/5 requests per 10s per caller).
- `POST /wake-up` is hit by the frontend when the user opens the chat, so the
  Lambda cold-starts before they finish typing their first message. It's
  throttled the same way as `/schedule-meeting` (KV, hashed IP + User-Agent
  key) but with its own `WAKE_UP_BLOCKS` namespace and a 2h `expirationTtl`:
  the first call in a 2h window is proxied to the Lambda as usual (response
  `{"message": "warm up started"}`); every other call in that window is
  answered directly by the worker with `{"message": "redirected"}` and never
  reaches the Lambda.

## Setup

```bash
npm install
```

## Configuration

Non-secret config lives in `wrangler.toml`:

- `LAMBDA_URL` — the Lambda Function URL to proxy to.
- `ALLOWED_ORIGINS` — comma-separated list of origins allowed to call this worker.
- `SCHEDULE_MEETING_BLOCKS` — KV namespace backing the 24h `/schedule-meeting`
  cooldown, created via:

  ```bash
  npx wrangler kv namespace create SCHEDULE_MEETING_BLOCKS
  ```

  (the resulting `id` is already wired into `wrangler.toml`).

- `WAKE_UP_BLOCKS` — KV namespace backing the 2h `/wake-up` throttle, created via:

  ```bash
  npx wrangler kv namespace create WAKE_UP_BLOCKS
  ```

  then replace the placeholder `id` under `WAKE_UP_BLOCKS` in `wrangler.toml`
  with the one it prints.

Secrets (already created per the task, set via the Cloudflare dashboard or
`wrangler secret put`, never committed):

```bash
wrangler secret put AWS_ACCESS_KEY_ID
wrangler secret put AWS_SECRET_ACCESS_KEY
wrangler secret put AWS_REGION
```

These must belong to an IAM principal with `lambda:InvokeFunctionUrl` on the
target function, and the Function URL must have `AuthType: AWS_IAM`.

## Develop & deploy

```bash
npm run dev      # wrangler dev — local server at http://localhost:8787
npm run deploy   # wrangler deploy
npm run tail     # wrangler tail — live production logs
```

After deploying, point the frontend (`DavidSergeev.github.io`) at this
worker's URL instead of the raw Lambda Function URL.
