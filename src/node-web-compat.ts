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
import { FetchError, NonRetryableFetchError } from "./error.js";

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
  defaultFetchTimeouts: {
    socketIdle?: number; // socket idle timeout (Only supported by Node.js runtime)
    response: number; // total round trip timeout
  };
}

/**
 * Sanity check a HTTPS response where we expect to get JSON data back
 *
 * @param uri the uri that was being requested
 * @param statusCode the HTTP status code, should be 200
 * @param contentType the value of the "Content-Type" header in the response, should start with "application/json"
 * @returns void - throws an error if the status code or content type aren't as expected
 */
export function validateHttpsJsonResponse(
  uri: string,
  statusCode?: number,
  contentType?: string
): void {
  if (statusCode === 429) {
    throw new FetchError(uri, "Too many requests");
  } else if (statusCode !== 200) {
    throw new NonRetryableFetchError(
      uri,
      `Status code is ${statusCode}, expected 200`
    );
  }
  if (
    !contentType ||
    !contentType.toLowerCase().startsWith("application/json")
  ) {
    throw new NonRetryableFetchError(
      uri,
      `Content-type is "${contentType}", expected "application/json"`
    );
  }
}
