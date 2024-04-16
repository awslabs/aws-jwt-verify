// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// NodeJS implementation for fetching JSON documents over HTTPS

import { request } from "https";
import { RequestOptions } from "http";
import { validateHttpsBufferResponse, validateHttpsJsonResponse } from "./https-common.js";
import { TextDecoder } from "util";
import { safeJsonParse, Json } from "./safe-json-parse.js";
import { FetchError, NonRetryableFetchError } from "./error.js";
import { IncomingMessage } from "http";

/**
 * Interface for Request Options, that adds one additional option to the Node.js standard RequestOptions,
 * "responseTimeout", with which a timeout can be set within which the response must be received.
 * (Note the "timeout" in the Node.js standard RequestOptions, concerns something else: the socket idle timeout)
 */
type FetchRequestOptions = RequestOptions & {
  responseTimeout?: number;
};

/**
 * Execute a HTTPS request
 * @param uri - The URI
 * @param parseResponse - Function to parse the response
 * @param responseValidation - Function to validate the response
 * @param requestOptions - The RequestOptions to use
 * @param data - Data to send to the URI (e.g. POST data)
 * @returns - The response as parsed JSON
 */
async function fetch<Resultype>(
  uri: string,
  responseValidation: (response: IncomingMessage) => void,
  parseResponse: (data: Buffer[]) => Resultype,
  requestOptions?: FetchRequestOptions,
  data?: Uint8Array,
): Promise<Resultype> {
  let responseTimeout: NodeJS.Timeout;
  return new Promise<Resultype>((resolve, reject) => {
    const req = request(
      uri,
      {
        method: "GET",
        ...requestOptions,
      },
      (response) => {
        try {
          responseValidation(response);
        } catch(error) {
          rejectWithCustomError(error);
        }

        // Collect response body data.
        var responseData = [] as Buffer[];
        response.on('data', chunk => {
          responseData.push(chunk);
        });

        response.on('end', () => {
          try {
            resolve(parseResponse(responseData));
          } catch(error) {
            rejectWithCustomError(new NonRetryableFetchError(uri, error));
          }
        });
      }
    );

    if (requestOptions?.responseTimeout) {
      responseTimeout = setTimeout(
        () =>
          rejectWithCustomError(
            new FetchError(
              uri,
              `Response time-out (after ${requestOptions.responseTimeout} ms.)`
            )
          ),
        requestOptions.responseTimeout
      );
      responseTimeout.unref(); // Don't block Node from exiting
    }

    function rejectWithCustomError(error: any) {
      // In case of errors, let the Agent (if any) know to abandon the socket
      // This is probably best, because the socket may have become stale
      /* istanbul ignore next */
      req.socket?.emit("agentRemove");

      // Turn error into FetchError so the URI is nicely captured in the message
      if (!(error instanceof FetchError)) {
        error = new FetchError(uri, error.message);
      }

      req.destroy();
      reject(error);
    }

    if (responseTimeout){
      req.on("close", () => clearTimeout(responseTimeout));
    }

    // Handle errors while sending request
    req.on("error", error => {
      rejectWithCustomError(error);
    });

    // Signal end of request (include optional data)
    req.end(data);
  });
}

/**
 * Execute a HTTPS request
 * @param uri - The URI
 * @param requestOptions - The RequestOptions to use
 * @param data - Data to send to the URI (e.g. POST data)
 * @returns - The response as parsed JSON
 */
export async function fetchBuffer<ResultType extends Buffer>(
  uri: string,
  requestOptions?: FetchRequestOptions,
  data?: Uint8Array,
): Promise<ResultType> {
  return fetch(
    uri,
    response=>validateHttpsBufferResponse(uri, response.statusCode),
    (data: Buffer[]) => Buffer.concat(data) as ResultType,
    requestOptions,
    data);
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
  data?: Uint8Array
): Promise<ResultType> {
  return fetch(
    uri, 
    response=>validateHttpsJsonResponse(uri, response.statusCode, response.headers["content-type"]),  
    (data: Buffer[]) => {
      return safeJsonParse(
        new TextDecoder("utf8", { fatal: true, ignoreBOM: true }).decode(
          Buffer.concat(data)
        )
      ) as ResultType;
    }, 
    requestOptions,
    data
  );
}

