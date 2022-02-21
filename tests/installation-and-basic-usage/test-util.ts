/**
 * Stand-alone and trimmed down copy of tests/unit/test-util.ts
 * Copied here so that the test in this dir is fully independent of aws-jwt-verify sources,
 * and only depends on the aws-jwt-verify package
 */

import { createSign, generateKeyPairSync, KeyObject } from "crypto";
import { deconstructPublicKeyInDerFormat } from "aws-jwt-verify/asn1";
import { Jwk, Jwks } from "aws-jwt-verify/jwk";

export function generateKeyPair() {
  const { privateKey, publicKey } = generateKeyPairSync("rsa", {
    modulusLength: 4096,
    publicExponent: 0x10001,
  });
  const jwk = publicKeyToJwk(publicKey);

  return {
    privateKey,
    jwks: { keys: [jwk] } as Jwks,
    jwk,
  };
}

export function publicKeyToJwk(publicKey: KeyObject) {
  const { n, e } = deconstructPublicKeyInDerFormat(
    publicKey.export({ format: "der", type: "spki" })
  );
  return {
    kid: "testkid",
    alg: "RS256",
    kty: "RSA",
    use: "sig",
    n: Buffer.from(n).toString("base64"),
    e: Buffer.from(e).toString("base64"),
  } as Jwk;
}

export function signJwt(
  header: { kid: string; alg: string },
  payload: { [key: string]: any },
  privateKey: KeyObject,
  produceValidSignature = true
) {
  const toSign = [
    base64url(JSON.stringify(header)),
    base64url(JSON.stringify(payload)),
  ].join(".");
  const sign = createSign("RSA-SHA256");
  sign.write(toSign);
  sign.end();
  const signature = sign.sign(privateKey);
  if (!produceValidSignature) {
    signature[0] = ~signature[0]; // swap first byte
  }
  const signedJwt = [toSign, base64url(signature)].join(".");
  return signedJwt;
}

export function base64url(x: string | Buffer) {
  if (typeof x === "string") {
    x = Buffer.from(x);
  }
  return x
    .toString("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}
