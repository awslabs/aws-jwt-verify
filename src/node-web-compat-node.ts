// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Node.js implementations for the node-web-compatibility layer

import { createPublicKey, createVerify, KeyObject } from "crypto";
import { SignatureJwk } from "./jwk.js";
import { fetch } from "./https-node.js";
import { NodeWebCompat } from "./node-web-compat.js";

/**
 * Enum to map supported JWT signature algorithms with OpenSSL message digest algorithm names
 */
enum JwtSignatureAlgorithms {
  RS256 = "RSA-SHA256",
  RS384 = "RSA-SHA384",
  RS512 = "RSA-SHA512",
  ES256 = RS256, // yes, openssl uses the same algorithm name
  ES384 = RS384, // yes, openssl uses the same algorithm name
  ES512 = RS512, // yes, openssl uses the same algorithm name
}

export const nodeWebCompat: NodeWebCompat = {
  fetch,
  transformJwkToKeyObjectSync: (jwk: SignatureJwk) =>
    createPublicKey({
      key: jwk,
      format: "jwk",
    }),
  transformJwkToKeyObjectAsync: async (jwk: SignatureJwk) =>
    createPublicKey({
      key: jwk,
      format: "jwk",
    }),
  parseB64UrlString: (b64: string): string =>
    Buffer.from(b64, "base64").toString("utf8"),
  verifySignatureSync: ({ alg, keyObject, jwsSigningInput, signature }) =>
    // eslint-disable-next-line security/detect-object-injection
    createVerify(JwtSignatureAlgorithms[alg])
      .update(jwsSigningInput)
      .verify(
        {
          key: keyObject as KeyObject,
          dsaEncoding: "ieee-p1363", // Signature format r || s (not used for RSA)
        },
        signature,
        "base64"
      ),
  verifySignatureAsync: async ({
    alg,
    keyObject,
    jwsSigningInput,
    signature,
  }) =>
    // eslint-disable-next-line security/detect-object-injection
    createVerify(JwtSignatureAlgorithms[alg])
      .update(jwsSigningInput)
      .verify(
        {
          key: keyObject as KeyObject,
          dsaEncoding: "ieee-p1363", // Signature format r || s (not used for RSA)
        },
        signature,
        "base64"
      ),
  defaultFetchTimeouts: {
    socketIdle: 1500,
    response: 3000,
  },
  setTimeoutUnref: (...args: Parameters<typeof setTimeout>) =>
    setTimeout(...args).unref(),
};
