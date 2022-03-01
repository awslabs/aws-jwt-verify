// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Compatibility layer, to make this lib work in both Node.js and Web
// This file just contains stubs for typings

import { Json } from "./safe-json-parse.js";
import {
  JwkToKeyObjectTransformerSync,
  JwkToKeyObjectTransformerAsync,
  JwsVerificationFunctionSync,
  JwsVerificationFunctionAsync,
} from "./jwt-rsa";

export interface NodeWebCompat {
  transformJwkToKeyObjectSync: JwkToKeyObjectTransformerSync;
  transformJwkToKeyObjectAsync: JwkToKeyObjectTransformerAsync;
  verifySignatureSync: JwsVerificationFunctionSync;
  verifySignatureAsync: JwsVerificationFunctionAsync;
  parseB64UrlString: (b64: string) => string;
  fetchJson: <ResultType extends Json>(
    uri: string,
    requestOptions?: Record<string, unknown>,
    data?: Uint8Array
  ) => Promise<ResultType>;
}
