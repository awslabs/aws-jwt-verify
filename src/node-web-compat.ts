// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Compatibility layer, to make this lib work in both Node.js and Web

import { Json } from "./safe-json-parse.js";

// Crypto functions
export let createVerify: (algorithm: string) => {
  update: (payload: string) => {
    verify: (
      keyObject: KeyObject,
      signature: string,
      encoding: "base64"
    ) => boolean;
  };
};
export let createPublicKey: (_: {
  key: Uint8Array;
  format: "der";
  type: "spki";
}) => KeyObject;
export type KeyObject = {
  export: (_: { format: "der"; type: "spki" }) => unknown;
};

// Path functions
export let join: (...segments: string[]) => string;

// Buffer (Uint8) functions
export let concatUint8Arrays: (...arrays: Uint8Array[]) => Uint8Array;
export let numberFromUint8ArrayBE: (_: Uint8Array, length: number) => number;
export let uint8ArrayFromString: (_: string, encoding: "base64") => Uint8Array;

// Fetch JSON
export let fetchJson: <ResultType extends Json>(
  uri: string,
  requestOptions?: Record<string, unknown>,
  data?: Uint8Array
) => Promise<ResultType>;
