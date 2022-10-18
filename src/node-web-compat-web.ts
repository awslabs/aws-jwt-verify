// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Web implementations for the node-web-compatibility layer

import {
  FetchError,
  NotSupportedError,
  JwtInvalidSignatureAlgorithmError,
} from "./error.js";
import { NodeWebCompat } from "./node-web-compat.js";
import { validateHttpsJsonResponse } from "./https-common.js";
import { Json, safeJsonParse } from "./safe-json-parse.js";

/**
 * Enum to map supported JWT signature algorithms with WebCrypto message digest algorithm names
 */
enum JwtSignatureAlgorithmsWebCrypto {
  RS256 = "SHA-256",
  RS384 = "SHA-384",
  RS512 = "SHA-512",
}

export const nodeWebCompat: NodeWebCompat = {
  fetchJson: async <ResultType extends Json>(
    uri: string,
    requestOptions?: Record<string, unknown>,
    data?: Uint8Array
  ) => {
    const responseTimeout = Number(requestOptions?.["responseTimeout"]);
    if (responseTimeout) {
      const abort = new AbortController();
      setTimeout(
        () =>
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          (abort.abort as any)(
            new FetchError(
              uri,
              `Response time-out (after ${responseTimeout} ms.)`
            )
          ),
        responseTimeout
      );
      requestOptions = { signal: abort.signal, ...requestOptions };
    }
    const response = await fetch(uri, { ...requestOptions, body: data });
    validateHttpsJsonResponse(
      uri,
      response.status,
      response.headers.get("content-type") ?? undefined
    );
    return response.text().then((text) => safeJsonParse(text) as ResultType);
  },
  defaultFetchTimeouts: {
    response: 3000,
  },
  transformJwkToKeyObjectSync: () => {
    throw new NotSupportedError(
      "Synchronously transforming a JWK into a key object is not supported in the browser"
    );
  },
  transformJwkToKeyObjectAsync: (jwk, jwtHeaderAlg) => {
    const alg =
      (jwk.alg as keyof typeof JwtSignatureAlgorithmsWebCrypto) ?? jwtHeaderAlg;
    if (!alg) {
      throw new JwtInvalidSignatureAlgorithmError(
        "Missing alg on both JWK and JWT header",
        alg
      );
    }
    return window.crypto.subtle.importKey(
      "jwk",
      jwk,
      {
        name: "RSASSA-PKCS1-v1_5",
        hash: JwtSignatureAlgorithmsWebCrypto[
          alg as keyof typeof JwtSignatureAlgorithmsWebCrypto
        ],
      },
      false,
      ["verify"]
    );
  },
  verifySignatureSync: () => {
    throw new NotSupportedError(
      "Synchronously verifying a JWT signature is not supported in the browser"
    );
  },
  verifySignatureAsync: ({ jwsSigningInput, keyObject, signature }) =>
    window.crypto.subtle.verify(
      {
        name: "RSASSA-PKCS1-v1_5",
      },
      keyObject as CryptoKey,
      bufferFromBase64url(signature),
      new TextEncoder().encode(jwsSigningInput)
    ),
  parseB64UrlString: (b64: string): string =>
    new TextDecoder().decode(bufferFromBase64url(b64)),
  setTimeoutUnref: window.setTimeout.bind(window),
};

const bufferFromBase64url = (function () {
  const map = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    .split("")
    .reduce(
      (acc, char, index) => Object.assign(acc, { [char.charCodeAt(0)]: index }),
      {} as { [key: number]: number }
    );
  return function (base64url: string) {
    const paddingLength = base64url.match(/^.+?(=?=?)$/)![1].length;
    let first: number, second: number, third: number, fourth: number;
    return base64url.match(/.{1,4}/g)!.reduce((acc, chunk, index) => {
      first = map[chunk.charCodeAt(0)];
      second = map[chunk.charCodeAt(1)];
      third = map[chunk.charCodeAt(2)];
      fourth = map[chunk.charCodeAt(3)];
      acc[3 * index] = (first << 2) | (second >> 4);
      acc[3 * index + 1] = ((second & 0b1111) << 4) | (third >> 2);
      acc[3 * index + 2] = ((third & 0b11) << 6) | fourth;
      return acc;
    }, new Uint8Array((base64url.length * 3) / 4 - paddingLength));
  };
})();
