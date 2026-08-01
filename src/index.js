/**
 * Reverse proxy in front of the landing page's AWS Lambda Function URL.
 *
 * The Lambda Function URL is locked down with AuthType: AWS_IAM (see
 * landing-page-backend/template.yaml), so anonymous requests are rejected
 * by AWS itself. This worker holds the only credentials allowed to invoke
 * it: every incoming request is re-signed with AWS Signature V4 (service
 * "lambda") using the AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / AWS_REGION
 * secrets, then forwarded upstream. This also keeps the real Function URL
 * out of the public frontend bundle.
 *
 * Only the two endpoints exposed by landing-page-backend/src/main.py are
 * proxied:
 *   POST /                 streaming SSE chat (forwarded byte-for-byte,
 *                           including the streamed response body)
 *   POST /schedule-meeting  "Hire me" modal form (buffered JSON)
 *
 * CORS is enforced here (checked against ALLOWED_ORIGINS) since the Lambda's
 * own CORS middleware can't see the true browser Origin once IAM auth is in
 * front of it.
 */
import { SignatureV4 } from "@aws-sdk/signature-v4";
import { Sha256 } from "@aws-crypto/sha256-js";

const ALLOWED_METHODS = "POST, OPTIONS";
const ALLOWED_HEADERS = "Content-Type";
const ALLOWED_PATHS = new Set(["/", "/schedule-meeting"]);

function corsHeaders(origin, allowedOrigins) {
  const headers = new Headers({
    "Access-Control-Allow-Methods": ALLOWED_METHODS,
    "Access-Control-Allow-Headers": ALLOWED_HEADERS,
    "Access-Control-Max-Age": "86400",
    Vary: "Origin",
  });
  if (origin && allowedOrigins.includes(origin)) {
    headers.set("Access-Control-Allow-Origin", origin);
  }
  return headers;
}

async function signRequest(env, targetUrl, body, contentType) {
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
    protocol: targetUrl.protocol,
    hostname: targetUrl.hostname,
    path: targetUrl.pathname,
    query: {},
    headers: {
      host: targetUrl.hostname,
      "content-type": contentType,
    },
    body,
  });
}

export default {
  async fetch(request, env, ctx) {
    const origin = request.headers.get("Origin") || "";
    const allowedOrigins = (env.ALLOWED_ORIGINS || "").split(",").map((o) => o.trim());
    const cors = corsHeaders(origin, allowedOrigins);

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: cors });
    }

    const { pathname } = new URL(request.url);
    if (!ALLOWED_PATHS.has(pathname)) {
      return new Response("Not found", { status: 404, headers: cors });
    }
    if (request.method !== "POST") {
      return new Response("Method not allowed", { status: 405, headers: cors });
    }

    const targetUrl = new URL(env.LAMBDA_URL);
    targetUrl.pathname = pathname;

    const body = await request.text();
    const contentType = request.headers.get("Content-Type") || "application/json";

    let signed;
    try {
      signed = await signRequest(env, targetUrl, body, contentType);
    } catch (err) {
      return new Response("Failed to sign upstream request", { status: 500, headers: cors });
    }

    const upstreamResponse = await fetch(targetUrl.toString(), {
      method: "POST",
      headers: signed.headers,
      body: signed.body,
    });

    console.log("Lambda status:", upstreamResponse.status);

    const text = await upstreamResponse.text();

    console.log("Lambda body:", text);

    return new Response(text, {
      status: upstreamResponse.status,
      headers: cors,
    });
  },
};
