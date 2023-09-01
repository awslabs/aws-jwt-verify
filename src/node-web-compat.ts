// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// To make this library work in both Node.js and Web, some functions require specific code,
// e.g. in Node.js we can use the "crypto" module, whereas in Web we need to use SubtleCrypto.
// This file contains an interface that the specific Node.js and Web implementations must implement.
//
// At runtime, either the Node.js or Web implementation is actually loaded. This works because the
// package.json specifies "#node-web-compat" as a subpath import, with conditions pointing to the right implementation (for Node.js or Web)

import { Json } from "./safe-json-parse.js";
import { EsSignatureJwk, RsaSignatureJwk } from "./jwk.js";
import {
  JwsVerificationFunctionAsync,
  JwsVerificationFunctionSync,
  GenericKeyObject,
} from "./jwt.js";
import { SupportedSignatureAlgorithm as SupportedSignatureAlgorithmEs } from "./jwt-es.js";
import { SupportedSignatureAlgorithm as SupportedSignatureAlgorithmRsa } from "./jwt-rsa.js";

/**
 * Interface that the specific Node.js and Web implementations must implement
 */
export interface NodeWebCompat {
  transformJwkToKeyObjectSync: (
    jwk: RsaSignatureJwk | EsSignatureJwk,
    jwtHeaderAlg?:
      | SupportedSignatureAlgorithmEs
      | SupportedSignatureAlgorithmRsa
  ) => GenericKeyObject;
  transformJwkToKeyObjectAsync: (
    jwk: RsaSignatureJwk | EsSignatureJwk,
    jwtHeaderAlg?:
      | SupportedSignatureAlgorithmEs
      | SupportedSignatureAlgorithmRsa
  ) => Promise<GenericKeyObject>;
  verifySignatureSync: JwsVerificationFunctionSync<
    SupportedSignatureAlgorithmEs | SupportedSignatureAlgorithmRsa
  >;
  verifySignatureAsync: JwsVerificationFunctionAsync<
    SupportedSignatureAlgorithmEs | SupportedSignatureAlgorithmRsa
  >;
  parseB64UrlString: (b64: string) => string;
  setTimeoutUnref: (
    ...args: Parameters<typeof setTimeout>
  ) => ReturnType<typeof setTimeout>;
  fetchJson: <ResultType extends Json>(
    uri: string,
    requestOptions?: Record<string, unknown>,
    data?: Uint8Array
  ) => Promise<ResultType>;
  defaultFetchTimeouts: {
    socketIdle?: number; // socket idle timeout (Only supported by Node.js runtime)
    response: number; // total round trip timeout
  };
}
