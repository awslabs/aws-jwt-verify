// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Web implementations for the node-web-compatibility layer

import {
  JwkToKeyObjectTransformerSync,
  JwkToKeyObjectTransformerAsync,
  JwsVerificationFunctionSync,
  JwsVerificationFunctionAsync,
} from "./jwt-rsa.js";
import { Jwk } from "./jwk.js";
import { Json } from "./safe-json-parse.js";
import { NotSupportedError } from "./error.js";

export const fetchJson: <ResultType extends Json>(
  uri: string,
  requestOptions?: Record<string, unknown>,
  data?: Uint8Array
) => Promise<ResultType> = (uri, requestOptions, data) =>
  fetch(uri, { ...requestOptions, body: data }).then((res) => res.json());

export const transformJwkToKeyObjectSync: JwkToKeyObjectTransformerSync =
  () => {
    throw new NotSupportedError(
      "Synchronously transforming a JWK into a key object is not supported in the browser"
    );
  };
export const verifySignatureSync: JwsVerificationFunctionSync = () => {
  throw new NotSupportedError(
    "Synchronously verifying a JWT signature is not supported in the browser"
  );
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

export const verifySignatureAsync: JwsVerificationFunctionAsync = ({
  jwsSigningInput,
  keyObject,
  signature,
}) =>
  window.crypto.subtle.verify(
    // eslint-disable-next-line security/detect-object-injection
    {
      name: "RSASSA-PKCS1-v1_5",
    },
    keyObject as CryptoKey,
    bufferFromBase64url(signature),
    new TextEncoder().encode(jwsSigningInput)
  );

export const utf8StringFromB64String = (b64: string): string => {
  return new TextDecoder().decode(bufferFromBase64url(b64));
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
