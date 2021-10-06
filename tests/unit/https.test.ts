import { fetchJson, SimpleJsonFetcher } from "../../src/https";
import { mockHttpsUri, throwOnUnusedMocks } from "./test-util";

describe("unit tests https", () => {
  afterEach(() => {
    throwOnUnusedMocks();
  });

  test("Fetch JSON happy flow works", () => {
    const uri = "https://example.com/test/jwks.json";
    const payload = { hello: "world" };
    mockHttpsUri(uri, { responsePayload: JSON.stringify(payload) });
    expect.assertions(1);
    return expect(fetchJson(uri)).resolves.toEqual(payload);
  });

  test("Fetch JSON error flow works: invalid JSON", () => {
    const uri = "https://example.com/test/jwks.json";
    const payload = JSON.stringify({ hello: "world" }) + "}";
    mockHttpsUri(uri, { responsePayload: payload });
    expect.assertions(1);
    return expect(fetchJson(uri)).rejects.toThrow(
      "Unexpected token } in JSON at position 17"
    );
  });

  test("Fetch JSON error flow works: 404", () => {
    const uri = "https://example.com/test/jwks.json";
    const payload = { hello: "world" };
    mockHttpsUri(uri, {
      responsePayload: JSON.stringify(payload),
      responseStatus: 404,
    });
    expect.assertions(1);
    return expect(fetchJson(uri)).rejects.toThrow(
      "Failed to fetch https://example.com/test/jwks.json: Status code is 404, expected 200"
    );
  });

  test("Fetch JSON error flow works: wrong Content-Type", () => {
    const uri = "https://example.com/test/jwks.json";
    const payload = { hello: "world" };
    mockHttpsUri(uri, {
      responsePayload: JSON.stringify(payload),
      responseHeaders: { "Content-Type": "text/html" },
    });
    expect.assertions(1);
    return expect(fetchJson(uri)).rejects.toThrow(
      'Failed to fetch https://example.com/test/jwks.json: Content-type is "text/html", expected "application/json"'
    );
  });

  test("Fetch JSON error flow works: no Content-Type", () => {
    const uri = "https://example.com/test/jwks.json";
    const payload = { hello: "world" };
    mockHttpsUri(uri, {
      responsePayload: JSON.stringify(payload),
      responseHeaders: {},
    });
    expect.assertions(1);
    return expect(fetchJson(uri)).rejects.toThrow(
      'Failed to fetch https://example.com/test/jwks.json: Content-type is "undefined", expected "application/json"'
    );
  });

  test("Fetch JSON error flow works: TCP error", () => {
    const uri = "https://example.com/test/jwks.json";
    class TcpError extends Error {}
    mockHttpsUri(uri, new TcpError("Some TCP error occured"));
    expect.assertions(1);
    return expect(fetchJson(uri)).rejects.toThrow(
      "Failed to fetch https://example.com/test/jwks.json: Some TCP error occured"
    );
  });

  test("Fetch JSON error flow works: no UTF-8", () => {
    const uri = "https://example.com/test/jwks.json";
    mockHttpsUri(uri, {
      responsePayload: Buffer.from("ff", "hex"), // will be invalid UTF-8
      responseHeaders: { "Content-Type": "application/json" },
    });
    expect.assertions(1);
    return expect(fetchJson(uri)).rejects.toThrow(
      new RegExp(
        "Failed to fetch https://example.com/test/jwks.json: (.*) The encoded data was not valid for encoding utf-8"
      )
    );
  });

  test("Fetch JSON error flow works: response timeout", () => {
    const uri = "https://example.com/test/jwks.json";
    const payload = { hello: "world" };
    mockHttpsUri(uri, {
      responsePayload: JSON.stringify(payload),
      delayBody: 300,
    });
    expect.assertions(1);
    return expect(fetchJson(uri, { responseTimeout: 299 })).rejects.toThrow(
      "Failed to fetch https://example.com/test/jwks.json: Response time-out (after 299 ms.)"
    );
  });

  test("Simple JSON fetcher works", () => {
    const uri = "https://example.com/test/jwks.json";
    const payload = { hello: "world" };
    mockHttpsUri(uri, { responsePayload: JSON.stringify(payload) });
    expect.assertions(1);
    return expect(new SimpleJsonFetcher().fetch(uri)).resolves.toEqual(payload);
  });

  test("Simple JSON fetcher does retry once", () => {
    const uri = "https://example.com/test/jwks.json";
    const payload = { hello: "world" };
    class TcpError extends Error {}
    expect.assertions(1);
    mockHttpsUri(uri, new TcpError("Some TCP error occured"));
    mockHttpsUri(uri, { responsePayload: JSON.stringify(payload) });
    return expect(new SimpleJsonFetcher().fetch(uri)).resolves.toEqual(payload);
  });

  test("Simple JSON fetcher does retry HTTP 429", () => {
    const uri = "https://example.com/test/jwks.json";
    const payload = { hello: "world" };
    expect.assertions(1);
    mockHttpsUri(uri, {
      responseStatus: 429,
      responsePayload: "WE'RE BUSY RIGHT NOW",
    });
    mockHttpsUri(uri, { responsePayload: JSON.stringify(payload) });
    return expect(new SimpleJsonFetcher().fetch(uri)).resolves.toEqual(payload);
  });

  test("Simple JSON fetcher does not retry twice", () => {
    const uri = "https://example.com/test/jwks.json";
    class TcpError extends Error {}
    expect.assertions(1);
    mockHttpsUri(uri, new TcpError("1st TCP Error"));
    mockHttpsUri(uri, new TcpError("2nd TCP Error"));
    return expect(new SimpleJsonFetcher().fetch(uri)).rejects.toThrow(
      "Failed to fetch https://example.com/test/jwks.json: 2nd TCP Error"
    );
  });

  test("Simple JSON fetcher does not retry non-retryable errors", () => {
    const uri = "https://example.com/test/jwks.json";
    expect.assertions(1);
    mockHttpsUri(uri, { responseStatus: 500, responsePayload: "Nope!\nError" });
    return expect(new SimpleJsonFetcher().fetch(uri)).rejects.toThrow(
      "Failed to fetch https://example.com/test/jwks.json: Status code is 500, expected 200"
    );
  });

  test("Simple JSON fetcher uses defaults provided to the constructor", () => {
    const uri = "https://example.com/test/jwks.json";
    const payload = { hello: "world" };
    mockHttpsUri(uri, { responsePayload: JSON.stringify(payload) });
    expect.assertions(1);
    return expect(
      new SimpleJsonFetcher({
        defaultRequestOptions: { timeout: 100, responseTimeout: 150 },
      }).fetch(uri)
    ).resolves.toEqual(payload);
  });
});
