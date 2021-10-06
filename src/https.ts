// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Utilities for fetching the JWKS URI, to get the public keys with which to verify JWTs

import { request } from "https";
import { IncomingHttpHeaders, RequestOptions } from "http";
import { pipeline } from "stream";
import { TextDecoder } from "util";
import { safeJsonParse, Json } from "./safe-json-parse.js";
import { FetchError, NonRetryableFetchError } from "./error.js";

/** Interface for JS objects that can be used with the SimpleJsonFetcher */
export interface JsonFetcher<ResultType extends Json = Json> {
  fetch: (
    uri: string,
    requestOptions?: FetchRequestOptions,
    data?: Buffer
  ) => Promise<ResultType>;
}

/**
 * Interface for Request Options, that adds one additional option to the NodeJS standard RequestOptions,
 * "responseTimeout", with which a timeout can be set within which the response must be received.
 * (Note the "timeout" in the NodeJS standard RequestOptions, concerns something else: the socket idle timeout)
 */
type FetchRequestOptions = RequestOptions & {
  responseTimeout?: number;
};

/**
 * HTTPS Fetcher for URIs with JSON body
 *
 * @param defaultRequestOptions - The default RequestOptions to use on individual HTTPS requests
 */
export class SimpleJsonFetcher implements JsonFetcher {
  defaultRequestOptions: FetchRequestOptions;
  constructor(props?: { defaultRequestOptions?: FetchRequestOptions }) {
    this.defaultRequestOptions = {
      timeout: 500, // socket idle timeout
      responseTimeout: 1500, // total round trip timeout
      ...props?.defaultRequestOptions,
    };
  }

  /**
   * Execute a HTTPS request (with 1 immediate retry in case of errors)
   * @param uri - The URI
   * @param requestOptions - The RequestOptions to use
   * @param data - Data to send to the URI (e.g. POST data)
   * @returns - The response as parsed JSON
   */
  public async fetch<ResultType extends Json>(
    uri: string,
    requestOptions?: FetchRequestOptions,
    data?: Buffer
  ): Promise<ResultType> {
    requestOptions = { ...this.defaultRequestOptions, ...requestOptions };
    try {
      return await fetchJson<ResultType>(uri, requestOptions, data);
    } catch (err) {
      if (err instanceof NonRetryableFetchError) {
        throw err;
      }
      // Retry once, immediately
      return fetchJson<ResultType>(uri, requestOptions, data);
    }
  }
}

/**
 * Execute a HTTPS request
 * @param uri - The URI
 * @param requestOptions - The RequestOptions to use
 * @param data - Data to send to the URI (e.g. POST data)
 * @returns - The response as parsed JSON
 */
export async function fetchJson<ResultType extends Json>(
  uri: string,
  requestOptions?: FetchRequestOptions,
  data?: Buffer
): Promise<ResultType> {
  let responseTimeout: NodeJS.Timeout;
  return new Promise<ResultType>((resolve, reject) => {
    const req = request(
      uri,
      {
        method: "GET",
        ...requestOptions,
      },
      (response) => {
        // Capture response data
        // @types/node is incomplete so cast to any
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        (pipeline as any)(
          [
            response,
            getJsonDestination(uri, response.statusCode, response.headers),
          ],
          done
        );
      }
    );

    if (requestOptions?.responseTimeout) {
      responseTimeout = setTimeout(
        () =>
          done(
            new FetchError(
              uri,
              `Response time-out (after ${requestOptions.responseTimeout} ms.)`
            )
          ),
        requestOptions.responseTimeout
      );
      responseTimeout.unref(); // Don't block Node from exiting
    }

    function done(...args: [Error] | [null, ResultType]) {
      if (responseTimeout) clearTimeout(responseTimeout);
      if (args[0] == null) {
        resolve(args[1]);
        return;
      }

      // In case of errors, let the Agent (if any) know to abandon the socket
      // This is probably best, because the socket may have become stale
      /* istanbul ignore next */
      req.socket?.emit("agentRemove");

      // Turn error into FetchError so the URI is nicely captured in the message
      let error = args[0];
      if (!(error instanceof FetchError)) {
        error = new FetchError(uri, error.message);
      }

      req.destroy();
      reject(error);
    }

    // Handle errors while sending request
    req.on("error", done);

    // Signal end of request (include optional data)
    req.end(data);
  });
}

/**
 * Ensures the HTTPS response contains valid JSON
 *
 * @param uri - The URI you were requesting
 * @param statusCode - The response status code to your HTTPS request
 * @param headers - The response headers to your HTTPS request
 *
 * @returns - Async function that can be used as destination in a stream.pipeline, it will return the JSON, if valid, or throw an error otherwise
 */
function getJsonDestination(
  uri: string,
  statusCode: number | undefined,
  headers: IncomingHttpHeaders
) {
  return async (responseIterable: AsyncIterableIterator<Buffer>) => {
    if (statusCode === 429) {
      throw new FetchError(uri, "Too many requests");
    } else if (statusCode !== 200) {
      throw new NonRetryableFetchError(
        uri,
        `Status code is ${statusCode}, expected 200`
      );
    }
    if (
      !headers["content-type"]?.toLowerCase().startsWith("application/json")
    ) {
      throw new NonRetryableFetchError(
        uri,
        `Content-type is "${headers["content-type"]}", expected "application/json"`
      );
    }
    const collected = [] as Buffer[];
    for await (const chunk of responseIterable) {
      collected.push(chunk);
    }
    try {
      return safeJsonParse(
        new TextDecoder("utf8", { fatal: true, ignoreBOM: true }).decode(
          Buffer.concat(collected)
        )
      );
    } catch (err) {
      throw new NonRetryableFetchError(uri, err);
    }
  };
}
