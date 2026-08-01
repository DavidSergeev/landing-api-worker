import { SignatureV4 } from "@aws-sdk/signature-v4";
import { Sha256 } from "@aws-crypto/sha256-js";


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

    if (request.method !== "POST") {
      return new Response("Method not allowed", {
        status: 405,
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


    return new Response(
      response.body,
      {
        status: response.status,
        headers,
      }
    );
  }
};