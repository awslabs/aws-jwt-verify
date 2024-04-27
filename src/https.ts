// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Utilities for fetching the JWKS URI, to get the public keys with which to verify JWTs

import { Json } from "./safe-json-parse.js";
import { NonRetryableFetchError } from "./error.js";
import { nodeWebCompat } from "#node-web-compat";

/**
 * Execute a HTTPS request
 * @param uri - The URI
 * @param requestOptions - The RequestOptions to use (depending on the runtime context, either Node.js RequestOptions or Web Fetch init)
 * @param data - Data to send to the URI (e.g. POST data)
 * @returns - The response as parsed JSON
 */
export const fetchJson = nodeWebCompat.fetchJson;

/**
 * Execute a HTTPS request
 * @param uri - The URI
 * @param requestOptions - The RequestOptions to use (depending on the runtime context, either Node.js RequestOptions or Web Fetch init)
 * @param data - Data to send to the URI (e.g. POST data)
 * @returns - The response as Buffer
 */
export const fetchBuffer = nodeWebCompat.fetchBuffer;

type FetchRequestOptions = Record<string, unknown>;

/** Interface for JS objects that can be used with the SimpleJsonFetcher */
export interface JsonFetcher<ResultType extends Json = Json> {
  fetch: (
    uri: string,
    requestOptions?: FetchRequestOptions,
    data?: Buffer
  ) => Promise<ResultType>;
}

/** Interface for JS objects that can be used with the SimpleJsonFetcher */
export interface BufferFetcher<ResultType extends Uint8Array = Uint8Array> {
  fetch: (
    uri: string,
    requestOptions?: FetchRequestOptions,
    data?: Buffer
  ) => Promise<ResultType>;
}

/**
 * A fetcher that retries once on failure.
 * Use the decorator pattern
 */
export class RetryableFetcher<ResultType> {

  defaultRequestOptions: FetchRequestOptions;

  constructor(
    private fetcher:(
    uri: string,
    requestOptions?: Record<string, unknown>,
    data?: Uint8Array
  ) => Promise<ResultType>,
  props?: { defaultRequestOptions?: FetchRequestOptions }) {
    this.defaultRequestOptions = {
      timeout: nodeWebCompat.defaultFetchTimeouts.socketIdle,
      responseTimeout: nodeWebCompat.defaultFetchTimeouts.response,
      ...props?.defaultRequestOptions,
    };
  }

  public async fetch (
    uri: string,
    requestOptions?: FetchRequestOptions,
    data?: Buffer
  ):Promise<ResultType>{
    requestOptions = { ...this.defaultRequestOptions, ...requestOptions };
    try {
      return await this.fetcher(uri, requestOptions, data);
    } catch (err) {
      if (err instanceof NonRetryableFetchError) {
        throw err;
      }
      // Retry once, immediately
      return this.fetcher(uri, requestOptions, data);
    }
  }
}
/**
 * HTTPS Fetcher for URIs with JSON body
 *
 * @param defaultRequestOptions - The default RequestOptions to use on individual HTTPS requests
 */
export class SimpleJsonFetcher extends RetryableFetcher<Json> implements JsonFetcher {
  
  constructor(props?: { defaultRequestOptions?: FetchRequestOptions }) {
    super(fetchJson, props);
  }

}


/**
 * HTTPS Fetcher for URIs with Buffer body
 *
 * @param defaultRequestOptions - The default RequestOptions to use on individual HTTPS requests
 */
export class SimpleBufferFetcher extends RetryableFetcher<Buffer> implements BufferFetcher {

  constructor(props?: { defaultRequestOptions?: FetchRequestOptions }) {
    super(fetchBuffer, props);
  }

}