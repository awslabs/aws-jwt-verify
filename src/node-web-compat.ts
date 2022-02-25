// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Compatibility layer, to make this lib work in both Node.js and Web
// This file just contains stubs for typings, in the dist process this file is
// overwritten with either the Node.js or Web implementation

import { Json } from "./safe-json-parse.js";
import {
  JwkToKeyObjectTransformerSync,
  JwkToKeyObjectTransformerAsync,
  JwsVerificationFunctionSync,
  JwsVerificationFunctionAsync,
} from "./jwt-rsa";

// Convert base64 to UTF8
export let utf8StringFromB64String: (b64: string) => string;

// Fetch JSON
export let fetchJson: <ResultType extends Json>(
  uri: string,
  requestOptions?: Record<string, unknown>,
  data?: Uint8Array
) => Promise<ResultType>;

export let transformJwkToKeyObjectSync: JwkToKeyObjectTransformerSync;
export let transformJwkToKeyObjectAsync: JwkToKeyObjectTransformerAsync;
export let verifySignatureSync: JwsVerificationFunctionSync;
export let verifySignatureAsync: JwsVerificationFunctionAsync;
