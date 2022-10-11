// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Web implementations for the node-web-compatibility layer

import {
  FetchError,
  NotSupportedError,
  JwtInvalidSignatureAlgorithmError,
  JwtInvalidSignatureError,
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
  transformJwkToKeyObjectAsync: (jwk, alg) => {
    alg = (jwk.alg as keyof typeof JwtSignatureAlgorithmsWebCrypto) ?? alg;
    if (!alg) {
      throw new JwtInvalidSignatureAlgorithmError("Missing alg", alg);
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
  verifySignatureAsync: ({ jwsSigningInput, keyObject, signature }) => {
    let signatureAsBuffer: BufferSource;
    try {
      signatureAsBuffer = bufferFromBase64url(signature);
    } catch {
      throw new JwtInvalidSignatureError("Invalid signature");
    }
    return window.crypto.subtle.verify(
      {
        name: "RSASSA-PKCS1-v1_5",
      },
      keyObject as CryptoKey,
      signatureAsBuffer,
      new TextEncoder().encode(jwsSigningInput)
    );
  },
  parseB64UrlString: (b64: string): string =>
    new TextDecoder().decode(bufferFromBase64url(b64)),
  setTimeoutUnref: window.setTimeout.bind(window),
};

function bufferFromBase64url(base64url: string) {
  const base64 = base64url.replace(/-/g, "+").replace(/_/g, "/");
  return new Uint8Array(
    atob(base64)
      .split("")
      .map((c) => c.charCodeAt(0))
  );
}
