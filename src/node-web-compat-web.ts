// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  JwkToKeyObjectTransformerSync,
  JwkToKeyObjectTransformerAsync,
  JwsSignatureVerificationFunctionSync,
  JwsSignatureVerificationFunctionAsync,
} from "./jwt-rsa";
import { Jwk } from "./jwk";
import { Json } from "./safe-json-parse";

export const fetchJson: <ResultType extends Json>(
  uri: string,
  requestOptions?: Record<string, unknown>,
  data?: Uint8Array
) => Promise<ResultType> = (uri, requestOptions, data) =>
  // eslint-disable-next-line no-undef
  fetch(uri, { ...requestOptions, body: data }).then((res) => res.json());

export const transformJwkToKeyObjectSync: JwkToKeyObjectTransformerSync =
  () => {
    throw new Error("Sync not implemented");
  };
export const verifySignatureSync: JwsSignatureVerificationFunctionSync = () => {
  throw new Error("Sync not implemented");
};

/**
 * Transform the JWK into an RSA public key in WebCrypto native key object format
 *
 * @param jwk: the JWK
 * @returns the RSA public key in EbCrypto native key object format
 */
export const transformJwkToKeyObjectAsync: JwkToKeyObjectTransformerAsync = (
  jwk: Jwk
) => {
  return window.crypto.subtle.importKey(
    "jwk",
    jwk,
    {
      name: "RSASSA-PKCS1-v1_5",
      hash: {
        name: JwtSignatureAlgorithmsWebCrypto[
          jwk.alg as keyof typeof JwtSignatureAlgorithmsWebCrypto
        ],
      },
    },
    false,
    ["verify"]
  );
};

/**
 * Enum to map supported JWT signature algorithms with WebCrypto message digest algorithm names
 */
enum JwtSignatureAlgorithmsWebCrypto {
  RS256 = "SHA-256",
  RS384 = "SHA-384",
  RS512 = "SHA-512",
}

export const verifySignatureAsync: JwsSignatureVerificationFunctionAsync = ({
  alg,
  jwsSigningInput,
  keyObject,
  signature,
}) =>
  window.crypto.subtle.verify(
    // eslint-disable-next-line security/detect-object-injection
    {
      name: "RSASSA-PKCS1-v1_5",
    },
    keyObject,
    fromBase64url(signature),
    new TextEncoder().encode(jwsSigningInput)
  );

export const utf8StringFromB64String = (b64: string): string => {
  return new TextDecoder().decode(fromBase64url(b64));
};

// modified version of MIT licensed https://github.com/niklasvh/base64-arraybuffer
// TODO reimplement
/**
Copyright (c) 2012 Niklas von Hertzen

Permission is hereby granted, free of charge, to any person
obtaining a copy of this software and associated documentation
files (the "Software"), to deal in the Software without
restriction, including without limitation the rights to use,
copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following
conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.
 */
const chars =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const lookup = new Uint8Array(256);
for (let i = 0; i < chars.length; i++) {
  lookup[chars.charCodeAt(i)] = i;
}
export const fromBase64url = (base64url: string): ArrayBuffer => {
  const len = base64url.length;
  let bufferLength = len * 0.75,
    i,
    p = 0,
    encoded1,
    encoded2,
    encoded3,
    encoded4;
  if (base64url[len - 1] === "=") {
    bufferLength--;
    if (base64url[len - 2] === "=") {
      bufferLength--;
    }
  }
  const arraybuffer = new ArrayBuffer(bufferLength),
    bytes = new Uint8Array(arraybuffer);
  for (i = 0; i < len; i += 4) {
    encoded1 = lookup[base64url.charCodeAt(i)];
    encoded2 = lookup[base64url.charCodeAt(i + 1)];
    encoded3 = lookup[base64url.charCodeAt(i + 2)];
    encoded4 = lookup[base64url.charCodeAt(i + 3)];
    bytes[p++] = (encoded1 << 2) | (encoded2 >> 4);
    bytes[p++] = ((encoded2 & 15) << 4) | (encoded3 >> 2);
    bytes[p++] = ((encoded3 & 3) << 6) | (encoded4 & 63);
  }
  return arraybuffer;
};
