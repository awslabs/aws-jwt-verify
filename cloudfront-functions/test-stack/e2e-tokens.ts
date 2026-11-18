// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Test keys and tokens for e2e.sh that Cognito cannot give us (expired, ES256, unknown kid).
// The keys are made for this run only; e2e.sh puts their public JWKs in the KVS and
// removes them at the end. Usage: ts-node e2e-tokens.ts <issuer> <clientId>
// Prints JSON: { jwks: { <kid>: jwk }, tokens: { expired, es256, unknownKid } }

import { createSign, generateKeyPairSync, KeyObject, randomUUID } from "crypto";

const [issuer, clientId] = process.argv.slice(2);
if (!issuer || !clientId)
  throw new Error("Usage: e2e-tokens.ts <issuer> <clientId>");

const run = randomUUID().slice(0, 8);
const b64 = (v: object) => Buffer.from(JSON.stringify(v)).toString("base64url");

function sign(
  alg: "RS256" | "ES256",
  kid: string,
  key: KeyObject,
  payload: object
) {
  const input = `${b64({ alg, kid, typ: "JWT" })}.${b64(payload)}`;
  const signer = createSign("SHA256");
  signer.update(input);
  const signature = signer.sign({ key, dsaEncoding: "ieee-p1363" });
  return `${input}.${signature.toString("base64url")}`;
}

const rsa = generateKeyPairSync("rsa", { modulusLength: 2048 });
const ec = generateKeyPairSync("ec", { namedCurve: "P-256" });
const rsaKid = `e2e-rsa-${run}`;
const ecKid = `e2e-ec-${run}`;
const now = Math.floor(Date.now() / 1000);
const claims = (exp: number) => ({
  iss: issuer,
  sub: `e2e-${run}`,
  token_use: "access",
  client_id: clientId,
  iat: now - 60,
  exp,
});

process.stdout.write(
  JSON.stringify({
    jwks: {
      [rsaKid]: {
        ...rsa.publicKey.export({ format: "jwk" }),
        kid: rsaKid,
        alg: "RS256",
        use: "sig",
      },
      [ecKid]: {
        ...ec.publicKey.export({ format: "jwk" }),
        kid: ecKid,
        alg: "ES256",
        use: "sig",
      },
    },
    tokens: {
      rs256: sign("RS256", rsaKid, rsa.privateKey, claims(now + 3600)),
      expired: sign("RS256", rsaKid, rsa.privateKey, claims(now - 60)),
      es256: sign("ES256", ecKid, ec.privateKey, claims(now + 3600)),
      // Signed by a key whose kid is neither in the KVS nor in the Cognito JWKS
      unknownKid: sign(
        "RS256",
        `e2e-unknown-${run}`,
        rsa.privateKey,
        claims(now + 3600)
      ),
    },
  })
);
