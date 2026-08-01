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

- `POST /` and `POST /schedule-meeting` are the only routes proxied,
  matching the endpoints in `landing-page-backend/src/main.py`.
- Every proxied request is signed with `@aws-sdk/signature-v4` +
  `@aws-crypto/sha256-js` (pure-JS SHA-256, no Node crypto needed — works on
  Workers' V8 isolate runtime) before being forwarded to `LAMBDA_URL`.
- The chat endpoint's streamed SSE response (`AWS_LWA_INVOKE_MODE=response_stream`)
  is passed straight through — `upstreamResponse.body` is forwarded byte-for-byte,
  it is never buffered here.
- CORS is enforced in the worker (checked against `ALLOWED_ORIGINS`), since
  once the Lambda sits behind IAM auth its own `CORSMiddleware` no longer sees
  the real browser `Origin`.

## Setup

```bash
npm install
```

## Configuration

Non-secret config lives in `wrangler.toml`:

- `LAMBDA_URL` — the Lambda Function URL to proxy to.
- `ALLOWED_ORIGINS` — comma-separated list of origins allowed to call this worker.

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
