// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Utilities for fetching the JWKS URI, to get the public keys with which to verify JWTs

import { NonRetryableFetchError } from "./error.js";
import { nodeWebCompat } from "#node-web-compat";

/**
 * Execute a HTTPS request
 * @param uri - The URI
 * @param requestOptions - The RequestOptions to use (depending on the runtime context, either Node.js RequestOptions or Web Fetch init)
 * @param data - Data to send to the URI (e.g. POST data)
 * @returns - The response body as ArrayBuffer
 */
export const fetch = nodeWebCompat.fetch.bind(undefined);

type FetchRequestOptions = Record<string, unknown>;

/** Interface for JS objects that can be used as Fetcher */
export interface Fetcher {
  /**
   * Execute a HTTPS request
   * @param uri - The URI
   * @param requestOptions - The RequestOptions to use (depending on the runtime context, either Node.js RequestOptions or Web Fetch init)
   * @param data - Data to send to the URI (e.g. POST data)
   * @returns - The response body as ArrayBuffer
   */
  fetch: (
    uri: string,
    requestOptions?: FetchRequestOptions,
    data?: ArrayBuffer
  ) => Promise<ArrayBuffer>;
}

/**
 * HTTPS Fetcher. The fetch implementation has 1 immediate retry in case of errors
 *
 * @param defaultRequestOptions - The default RequestOptions to use on individual HTTPS requests
 *   (depending on the runtime context, either Node.js RequestOptions or Web Fetch init)
 */
export class SimpleFetcher implements Fetcher {
  defaultRequestOptions: FetchRequestOptions;
  constructor(props?: { defaultRequestOptions?: FetchRequestOptions }) {
    this.defaultRequestOptions = {
      timeout: nodeWebCompat.defaultFetchTimeouts.socketIdle,
      responseTimeout: nodeWebCompat.defaultFetchTimeouts.response,
      ...props?.defaultRequestOptions,
    };
  }

  /**
   * Execute a HTTPS request (with 1 immediate retry in case of errors)
   * @param uri - The URI
   * @param requestOptions - The RequestOptions to use (depending on the runtime context, either Node.js RequestOptions or Web Fetch init)
   * @param data - Data to send to the URI (e.g. POST data)
   * @returns - The response body as ArrayBuffer
   */
  public async fetch(
    uri: string,
    requestOptions?: FetchRequestOptions,
    data?: ArrayBuffer
  ): Promise<ArrayBuffer> {
    requestOptions = { ...this.defaultRequestOptions, ...requestOptions };
    try {
      return await fetch(uri, requestOptions, data);
    } catch (err) {
      if (err instanceof NonRetryableFetchError) {
        throw err;
      }
      // Retry once, immediately
      return fetch(uri, requestOptions, data);
    }
  }
}
