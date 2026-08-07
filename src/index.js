import { SignatureV4 } from "@aws-sdk/signature-v4";
import { Sha256 } from "@aws-crypto/sha256-js";

const SCHEDULE_MEETING_PATH = "/schedule-meeting";
const SCHEDULE_MEETING_BLOCK_TTL_SECONDS = 24 * 60 * 60;

// Must match MeetingScheduledStatus.NOT_SCHEDULED in
// landing-page-backend/src/agent_tools/tools.py — it's the only outcome that
// does NOT start the 24h cooldown, since no meeting record was actually created.
const SCHEDULE_MEETING_FAILURE_STATUS = "the meeting is not scheduled";

// Hit by the frontend when the user opens the chat, so the Lambda cold-starts
// ahead of the first real chat message. Only the first caller in any 2h
// window actually reaches the Lambda; every other call in that window is
// answered here as a no-op "redirected" so the Lambda isn't woken up (and
// billed) once per click.
const WAKE_UP_PATH = "/wake-up";
const WAKE_UP_BLOCK_TTL_SECONDS = 2 * 60 * 60;

// Fixed-window per-caller cap on the chat endpoint itself: the first chat
// call opens a 1h window, up to CHAT_RATE_LIMIT_MAX_CALLS calls are allowed
// inside it, and the window's expiry is never extended by later calls (unlike
// a sliding window) — once it lapses, the caller gets a fresh set of calls.
const CHAT_PATH = "/";
const CHAT_RATE_LIMIT_WINDOW_SECONDS = 60 * 60;
const CHAT_RATE_LIMIT_MAX_CALLS = 20;

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
async function buildScheduleMeetingBlockKey(ip, userAgent) {
  if (!ip) return null;
  return `sm-block:${await hashIdentity([ip, userAgent || ""])}`;
}

// Same (IP, User-Agent) identity as schedule-meeting, but a separate KV
// namespace/prefix and a much shorter (2h) TTL — this is a warm-up throttle,
// not an abuse guard.
async function buildWakeUpBlockKey(ip, userAgent) {
  if (!ip) return null;
  return `wu-block:${await hashIdentity([ip, userAgent || ""])}`;
}

// Same (IP, User-Agent) identity again, yet another namespace/prefix — this
// one backs the 1h/20-call chat cap.
async function buildChatRateLimitKey(ip, userAgent) {
  if (!ip) return null;
  return `chat-rl:${await hashIdentity([ip, userAgent || ""])}`;
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

// Answered directly by the worker, without ever reaching the Lambda — this is
// the expected, common-case response once a caller has already warmed up the
// Lambda within the last 2h.
function redirectedResponse(cors) {
  return new Response(
    JSON.stringify({ message: "redirected" }),
    {
      status: 200,
      headers: applySecurityHeaders(new Headers({
        ...cors,
        "Content-Type": "application/json",
      })),
    }
  );
}

function chatRateLimitedResponse(cors, retryAfterSeconds) {
  return new Response(
    JSON.stringify({ error: "You've reached the hourly chat limit. Please try again later." }),
    {
      status: 429,
      headers: applySecurityHeaders(new Headers({
        ...cors,
        "Content-Type": "application/json",
        "Retry-After": String(retryAfterSeconds),
      })),
    }
  );
}

/**
 * Reads the caller's current chat-window entry (`{ count, expiresAt }`) from
 * KV, starting a fresh CHAT_RATE_LIMIT_WINDOW_SECONDS-long window if none
 * exists yet or the stored one has lapsed. Returns `{ allowed: false,
 * retryAfterSeconds }` once `count` would exceed CHAT_RATE_LIMIT_MAX_CALLS,
 * otherwise increments and persists the count (via KV's absolute `expiration`,
 * so the window's original expiry is preserved rather than pushed out on every
 * call) and returns `{ allowed: true }`.
 *
 * This counts calls, not successful ones — the chat response is streamed SSE
 * and piped through untouched (see the Lambda proxy below), so unlike
 * schedule-meeting/wake-up there's no small buffered body to inspect after
 * the fact without breaking streaming.
 */
async function checkAndIncrementChatRateLimit(env, key) {
  const now = Math.floor(Date.now() / 1000);

  let entry = null;
  try {
    const raw = await env.CHAT_RATE_LIMITS.get(key);
    if (raw) entry = JSON.parse(raw);
  } catch (err) {
    console.error(`chat-rate-limit: failed to read/parse entry for ${key}: ${err.message}`);
  }

  if (!entry || typeof entry.expiresAt !== "number" || entry.expiresAt <= now) {
    entry = { count: 0, expiresAt: now + CHAT_RATE_LIMIT_WINDOW_SECONDS };
  }

  if (entry.count >= CHAT_RATE_LIMIT_MAX_CALLS) {
    return { allowed: false, retryAfterSeconds: entry.expiresAt - now };
  }

  entry.count += 1;
  try {
    // KV requires expirations at least 60s out; that can only fail here if
    // the window has (by now) under a minute left, in which case it's about
    // to close on its own anyway — fail open and let this call through
    // uncounted rather than block the user over a KV-side constraint.
    await env.CHAT_RATE_LIMITS.put(key, JSON.stringify(entry), { expiration: entry.expiresAt });
  } catch (err) {
    console.error(`chat-rate-limit: failed to persist entry for ${key}: ${err.message}`);
  }

  return { allowed: true };
}

async function signRequest(env, url, body, ip) {

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
      // Included in the SigV4 signature, so it can't be forged by anyone
      // without the Worker's AWS credentials — the Lambda can trust it as the
      // real caller IP. Lets the backend enforce its own per-user rate limits
      // (e.g. the agent's schedule_meeting tool call), which it otherwise has
      // no visibility into since it only ever sees this Worker as the caller.
      "x-real-ip": ip || "",
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
    const isWakeUp = pathname === WAKE_UP_PATH;
    const isChat = pathname === CHAT_PATH;
    const ip = request.headers.get("CF-Connecting-IP");

    // Checked up front so a blocked caller never reaches the Lambda (saves
    // invocations and never runs the meeting-scheduling side effects again).
    // This is a fast pre-filter only — the backend enforces the authoritative
    // per-user check (covering this endpoint AND the agent's schedule_meeting
    // tool call from "/"), since only it knows whether scheduling truly
    // succeeded and can key on attendee_email in addition to IP.
    let blockKey = null;
    if (isScheduleMeeting) {
      blockKey = await buildScheduleMeetingBlockKey(ip, request.headers.get("User-Agent"));
      if (blockKey && (await env.SCHEDULE_MEETING_BLOCKS.get(blockKey)) !== null) {
        console.log(`schedule-meeting: blocked ${blockKey}`);
        return tooManyRequestsResponse(cors);
      }
    }

    // Same idea, but for the chat warm-up ping: once a caller has woken the
    // Lambda up within the last 2h, every further call is answered here —
    // "redirected" — instead of invoking it again.
    let wakeUpBlockKey = null;
    if (isWakeUp) {
      wakeUpBlockKey = await buildWakeUpBlockKey(ip, request.headers.get("User-Agent"));
      if (wakeUpBlockKey && (await env.WAKE_UP_BLOCKS.get(wakeUpBlockKey)) !== null) {
        console.log(`wake-up: redirected ${wakeUpBlockKey}`);
        return redirectedResponse(cors);
      }
    }

    // 1h/20-call cap on the chat endpoint itself. The window opens on this
    // caller's first chat call (tracked in KV) and every call inside it
    // counts, whether or not the Lambda ends up answering successfully.
    if (isChat) {
      const chatKey = await buildChatRateLimitKey(ip, request.headers.get("User-Agent"));
      if (chatKey) {
        const { allowed, retryAfterSeconds } = await checkAndIncrementChatRateLimit(env, chatKey);
        if (!allowed) {
          console.log(`chat: rate-limited ${chatKey}`);
          return chatRateLimitedResponse(cors, retryAfterSeconds);
        }
      }
    }

    const body = await request.text();


    const targetUrl = new URL(env.LAMBDA_URL);
    targetUrl.pathname = pathname;


    const signed = await signRequest(
      env,
      targetUrl,
      body,
      ip
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
    // schedule-meeting and wake-up both return a single small JSON object, so
    // it's safe (and, for schedule-meeting, necessary to inspect `status`) to
    // buffer those here.
    if (!isScheduleMeeting && !isWakeUp) {
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

    if (wakeUpBlockKey && response.ok) {
      await env.WAKE_UP_BLOCKS.put(wakeUpBlockKey, "1", {
        expirationTtl: WAKE_UP_BLOCK_TTL_SECONDS,
      });
      console.log(`wake-up: throttle set for ${wakeUpBlockKey}`);
    }

    return new Response(bodyText, { status: response.status, headers });
  }
};