// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// NodeJS implementation for fetching documents over HTTPS

import { Transform } from "stream";
import { request } from "https";
import { RequestOptions } from "http";
import { pipeline } from "stream";
import { FetchError, NonRetryableFetchError } from "./error.js";

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
 * @param requestOptions - The RequestOptions to use
 * @param data - Data to send to the URI (e.g. POST data)
 * @returns - The response body as a Uit8Array
 */
export async function fetch(
  uri: string,
  requestOptions?: FetchRequestOptions,
  data?: ArrayBuffer
): Promise<ArrayBuffer> {
  let responseTimeout: NodeJS.Timeout;
  return new Promise<ArrayBuffer>((resolve, reject) => {
    const req = request(
      uri,
      {
        method: "GET",
        ...requestOptions,
      },
      (response) => {
        // check status
        if (response.statusCode === 429) {
          done(new FetchError(uri, "Too many requests"));
          return;
        } else if (response.statusCode !== 200) {
          done(
            new NonRetryableFetchError(
              uri,
              `Status code is ${response.statusCode}, expected 200`
            )
          );
          return;
        }
        // Collect response data
        pipeline(
          response,
          collector(),
          async (collector) => {
            for await (const collected of collector) {
              return collected;
            }
          },
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

    function done(err: Error | null, data?: ArrayBuffer) {
      if (responseTimeout) clearTimeout(responseTimeout);
      if (err == null) {
        resolve(data!);
        return;
      }

      // In case of errors, let the Agent (if any) know to abandon the socket
      // This is probably best, because the socket may have become stale
      /* istanbul ignore next */
      req.socket?.emit("agentRemove");

      // Turn error into FetchError so the URI is nicely captured in the message
      if (!(err instanceof FetchError)) {
        err = new FetchError(uri, err.message);
      }

      req.destroy();
      reject(err);
    }

    // Handle errors while sending request
    req.on("error", done);

    // Signal end of request (include optional data)
    req.end(data);
  });
}

/**
 * Function that returns a Transform stream, which collects the incoming chunks (in-memory) into 1 Buffer
 * @returns Transform
 */
function collector() {
  const collected: Buffer[] = [];
  return new Transform({
    transform: function (chunk: Buffer, _encoding, cb) {
      collected.push(chunk);
      cb();
    },
    final: function (cb) {
      this.push(Buffer.concat(collected));
      cb();
    },
  });
}
