import { SignatureV4 } from "@aws-sdk/signature-v4";
import { Sha256 } from "@aws-crypto/sha256-js";

const SCHEDULE_MEETING_PATH = "/schedule-meeting";
const SCHEDULE_MEETING_BLOCK_TTL_SECONDS = 24 * 60 * 60;

// Must match MeetingScheduledStatus.NOT_SCHEDULED in
// landing-page-backend/src/agent_tools/tools.py — it's the only outcome that
// does NOT start the 24h cooldown, since no meeting record was actually created.
const SCHEDULE_MEETING_FAILURE_STATUS = "the meeting is not scheduled";

function parseAllowedOrigins(env) {
  return (env.ALLOWED_ORIGINS || "").split(",").map((o) => o.trim()).filter(Boolean);
}

/** Builds the CORS response headers for a given request, or null if its Origin isn't allowlisted. */
function corsHeaders(request, env) {
  const origin = request.headers.get("Origin");
  if (!origin || !parseAllowedOrigins(env).includes(origin)) return null;

  return {
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Methods": "POST",
    "Access-Control-Allow-Headers": "content-type",
    "Access-Control-Max-Age": "86400",
    "Vary": "Origin",
  };
}

// This worker only ever serves JSON/SSE to the frontend (never HTML), so the
// CSP can be maximally locked down and there's no clickjacking surface — the
// headers below are still set defensively in case a client ever renders the
// response body directly.
const SECURITY_HEADERS = {
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "no-referrer",
  "Content-Security-Policy": "default-src 'none'",
  "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
  "Permissions-Policy": "geolocation=(), camera=(), microphone=()",
  "X-Permitted-Cross-Domain-Policies": "none",
};

/** Applies the static security headers to a Headers instance, mutating it in place. */
function applySecurityHeaders(headers) {
  for (const [key, value] of Object.entries(SECURITY_HEADERS)) {
    headers.set(key, value);
  }
  return headers;
}

/** Hex SHA-256 of the joined parts, via the runtime's native Web Crypto (no extra deps). */
async function hashIdentity(parts) {
  const data = new TextEncoder().encode(parts.join("|"));
  const digest = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// IP alone can over-block shared networks (NAT/VPN/CGNAT); pairing it with the
// User-Agent narrows that without storing either value in plaintext in KV.
async function buildScheduleMeetingBlockKey(request) {
  const ip = request.headers.get("CF-Connecting-IP");
  if (!ip) return null;
  const userAgent = request.headers.get("User-Agent") || "";
  return `sm-block:${await hashIdentity([ip, userAgent])}`;
}

function tooManyRequestsResponse(cors) {
  return new Response(
    JSON.stringify({ error: "You've already scheduled a meeting recently. Please try again in 24 hours." }),
    {
      status: 429,
      headers: applySecurityHeaders(new Headers({
        ...cors,
        "Content-Type": "application/json",
        "Retry-After": String(SCHEDULE_MEETING_BLOCK_TTL_SECONDS),
      })),
    }
  );
}

async function signRequest(env, url, body) {

  const signer = new SignatureV4({
    service: "lambda",
    region: env.AWS_REGION,

    credentials: {
      accessKeyId: env.AWS_ACCESS_KEY_ID,
      secretAccessKey: env.AWS_SECRET_ACCESS_KEY,
    },

    sha256: Sha256,
  });


  return signer.sign({
    method: "POST",

    protocol: url.protocol,

    hostname: url.hostname,

    path: url.pathname,

    query: {},

    headers: {
      host: url.hostname,
      "content-type": "application/json",
    },

    body,
  });
}


export default {

  async fetch(request, env) {

    const cors = corsHeaders(request, env);

    // Preflight — answered directly by the worker, never forwarded to Lambda.
    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: cors ? 204 : 403,
        headers: applySecurityHeaders(new Headers(cors ?? undefined)),
      });
    }

    if (request.method !== "POST") {
      return new Response("Method not allowed", {
        status: 405,
        headers: applySecurityHeaders(new Headers(cors ?? undefined)),
      });
    }

    if (!cors) {
      return new Response("Origin not allowed", {
        status: 403,
        headers: applySecurityHeaders(new Headers()),
      });
    }

    const pathname = new URL(request.url).pathname;
    const isScheduleMeeting = pathname === SCHEDULE_MEETING_PATH;

    // Checked up front so a blocked caller never reaches the Lambda (saves
    // invocations and never runs the meeting-scheduling side effects again).
    let blockKey = null;
    if (isScheduleMeeting) {
      blockKey = await buildScheduleMeetingBlockKey(request);
      if (blockKey && (await env.SCHEDULE_MEETING_BLOCKS.get(blockKey)) !== null) {
        console.log(`schedule-meeting: blocked ${blockKey}`);
        return tooManyRequestsResponse(cors);
      }
    }

    const body = await request.text();


    const targetUrl = new URL(env.LAMBDA_URL);
    targetUrl.pathname = pathname;


    const signed = await signRequest(
      env,
      targetUrl,
      body
    );


    const response = await fetch(
      targetUrl,
      {
        method: "POST",

        headers: signed.headers,

        body: signed.body,
      }
    );


    const headers = new Headers(response.headers);

    headers.delete("content-length");
    headers.delete("transfer-encoding");
    headers.delete("connection");

    for (const [key, value] of Object.entries(cors)) {
      headers.set(key, value);
    }
    applySecurityHeaders(headers);

    // The chat endpoint streams SSE (`response.body` piped through untouched);
    // schedule-meeting returns a single small JSON object, so it's safe (and
    // necessary, to inspect `status`) to buffer it here.
    if (!isScheduleMeeting) {
      return new Response(response.body, { status: response.status, headers });
    }

    const bodyText = await response.text();

    if (blockKey && response.ok) {
      try {
        const { status } = JSON.parse(bodyText);
        if (status !== SCHEDULE_MEETING_FAILURE_STATUS) {
          await env.SCHEDULE_MEETING_BLOCKS.put(blockKey, "1", {
            expirationTtl: SCHEDULE_MEETING_BLOCK_TTL_SECONDS,
          });
          console.log(`schedule-meeting: cooldown set for ${blockKey}`);
        }
      } catch (err) {
        // Malformed/unexpected body — err on the side of not blocking, but log it:
        // if the Lambda's response shape ever changes, this is what would silently
        // disable the cooldown, so it needs to be visible in `wrangler tail`.
        console.error(`schedule-meeting: failed to parse Lambda response for cooldown check: ${err.message}`);
      }
    }

    return new Response(bodyText, { status: response.status, headers });
  }
};