// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Node.js implementations for the node-web-compatibility layer

import { createPublicKey, createVerify, KeyObject } from "crypto";
import { EsSignatureJwk, RsaSignatureJwk } from "./jwk.js";
import { fetchJson } from "./https-node.js";
import { NodeWebCompat } from "./node-web-compat.js";

/**
 * Enum to map supported JWT signature algorithms with OpenSSL message digest algorithm names
 */
enum JwtSignatureAlgorithms {
  RS256 = "RSA-SHA256",
  RS384 = "RSA-SHA384",
  RS512 = "RSA-SHA512",
  ES256 = "RSA-SHA256",
  ES384 = "RSA-SHA384",
  ES512 = "RSA-SHA512",
}

export const nodeWebCompat: NodeWebCompat = {
  fetchJson,
  transformJwkToKeyObjectSync: (jwk: RsaSignatureJwk | EsSignatureJwk) =>
    createPublicKey({
      key: jwk,
      format: "jwk",
    }),
  transformJwkToKeyObjectAsync: async (jwk: RsaSignatureJwk | EsSignatureJwk) =>
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
      .verify(keyObject as KeyObject, signature, "base64"),
  verifySignatureAsync: async ({
    alg,
    keyObject,
    jwsSigningInput,
    signature,
  }) =>
    // eslint-disable-next-line security/detect-object-injection
    createVerify(JwtSignatureAlgorithms[alg])
      .update(jwsSigningInput)
      .verify(keyObject as KeyObject, signature, "base64"),
  defaultFetchTimeouts: {
    socketIdle: 500,
    response: 1500,
  },
  setTimeoutUnref: (...args: Parameters<typeof setTimeout>) =>
    setTimeout(...args).unref(),
};
