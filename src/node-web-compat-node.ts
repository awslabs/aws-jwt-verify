// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Node.js implementations for the node-web-compatibility layer

import { createPublicKey, createVerify, KeyObject } from "crypto";
import {
  JwkToKeyObjectTransformerSync,
  JwsVerificationFunctionSync,
} from "./jwt-rsa";
import { Jwk } from "./jwk.js";
import { constructPublicKeyInDerFormat } from "./asn1.js";
export { fetchJson } from "./https-node.js";
import { wrapResultInPromise } from "./typing-util.js";

/**
 * Transform the JWK into an RSA public key in Node.js native key object format
 *
 * @param jwk: the JWK
 * @returns the RSA public key in Node.js native key object format
 */
export const transformJwkToKeyObjectSync: JwkToKeyObjectTransformerSync = (
  jwk: Jwk
) =>
  createPublicKey({
    key: constructPublicKeyInDerFormat(
      Buffer.from(jwk.n, "base64"),
      Buffer.from(jwk.e, "base64")
    ),
    format: "der",
    type: "spki",
  });

export const transformJwkToKeyObjectAsync = wrapResultInPromise(
  transformJwkToKeyObjectSync
);

/**
 * Enum to map supported JWT signature algorithms with OpenSSL message digest algorithm names
 */
enum JwtSignatureAlgorithms {
  RS256 = "RSA-SHA256",
  RS384 = "RSA-SHA384",
  RS512 = "RSA-SHA512",
}

export const verifySignatureSync: JwsVerificationFunctionSync = ({
  alg,
  keyObject,
  jwsSigningInput,
  signature,
}) => {
  // eslint-disable-next-line security/detect-object-injection
  return createVerify(JwtSignatureAlgorithms[alg])
    .update(jwsSigningInput)
    .verify(keyObject as KeyObject, signature, "base64");
};

export const verifySignatureAsync = wrapResultInPromise(verifySignatureSync);

export const parseB64UrlString = (b64: string): string =>
  Buffer.from(b64, "base64").toString("utf8");
