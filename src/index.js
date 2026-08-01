import { SignatureV4 } from "@aws-sdk/signature-v4";
import { Sha256 } from "@aws-crypto/sha256-js";


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
        headers: cors ?? undefined,
      });
    }

    if (request.method !== "POST") {
      return new Response("Method not allowed", {
        status: 405,
        headers: cors ?? undefined,
      });
    }

    if (!cors) {
      return new Response("Origin not allowed", {
        status: 403,
      });
    }


    const body = await request.text();


    const targetUrl = new URL(env.LAMBDA_URL);
    targetUrl.pathname = new URL(request.url).pathname;


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


    return new Response(
      response.body,
      {
        status: response.status,
        headers,
      }
    );
  }
};