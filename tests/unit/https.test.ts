import { fetch, SimpleFetcher } from "../../src/https";
import { mockHttpsUri, throwOnUnusedMocks } from "./test-util";

describe("unit tests https", () => {
  afterEach(() => {
    throwOnUnusedMocks();
  });

  test("Fetch happy flow works", () => {
    const uri = "https://example.com/test/jwks.json";
    const payload = { hello: "world" };
    mockHttpsUri(uri, { responsePayload: JSON.stringify(payload) });
    expect.assertions(1);
    return expect(fetch(uri)).resolves.toEqual(
      Buffer.from(JSON.stringify(payload))
    );
  });

  test("Fetch error flow works: 404", () => {
    const uri = "https://example.com/test/jwks.json";
    const payload = { hello: "world" };
    mockHttpsUri(uri, {
      responsePayload: JSON.stringify(payload),
      responseStatus: 404,
    });
    expect.assertions(1);
    return expect(fetch(uri)).rejects.toThrow(
      "Failed to fetch https://example.com/test/jwks.json: Status code is 404, expected 200"
    );
  });

  test("Fetch error flow works: TCP error", () => {
    const uri = "https://example.com/test/jwks.json";
    class TcpError extends Error {}
    mockHttpsUri(uri, new TcpError("Some TCP error occured"));
    expect.assertions(1);
    return expect(fetch(uri)).rejects.toThrow(
      "Failed to fetch https://example.com/test/jwks.json: Some TCP error occured"
    );
  });

  test("Fetch error flow works: response timeout", () => {
    const uri = "https://example.com/test/jwks.json";
    const payload = { hello: "world" };
    mockHttpsUri(uri, {
      responsePayload: JSON.stringify(payload),
      delayBody: 300,
    });
    expect.assertions(1);
    return expect(fetch(uri, { responseTimeout: 299 })).rejects.toThrow(
      "Failed to fetch https://example.com/test/jwks.json: Response time-out (after 299 ms.)"
    );
  });

  test("Simple JSON fetcher works", () => {
    const uri = "https://example.com/test/jwks.json";
    const payload = { hello: "world" };
    mockHttpsUri(uri, { responsePayload: JSON.stringify(payload) });
    expect.assertions(1);
    return expect(new SimpleFetcher().fetch(uri)).resolves.toEqual(
      Buffer.from(JSON.stringify(payload))
    );
  });

  test("Simple JSON fetcher does retry once", () => {
    const uri = "https://example.com/test/jwks.json";
    const payload = { hello: "world" };
    class TcpError extends Error {}
    expect.assertions(1);
    mockHttpsUri(uri, new TcpError("Some TCP error occured"));
    mockHttpsUri(uri, { responsePayload: JSON.stringify(payload) });
    return expect(new SimpleFetcher().fetch(uri)).resolves.toEqual(
      Buffer.from(JSON.stringify(payload))
    );
  });

  test("Simple JSON fetcher does not retry twice", () => {
    const uri = "https://example.com/test/jwks.json";
    class TcpError extends Error {}
    expect.assertions(1);
    mockHttpsUri(uri, new TcpError("1st TCP Error"));
    mockHttpsUri(uri, new TcpError("2nd TCP Error"));
    return expect(new SimpleFetcher().fetch(uri)).rejects.toThrow(
      "Failed to fetch https://example.com/test/jwks.json: 2nd TCP Error"
    );
  });

  test("Simple JSON fetcher does not retry non-retryable errors", () => {
    const uri = "https://example.com/test/jwks.json";
    expect.assertions(1);
    mockHttpsUri(uri, { responseStatus: 500, responsePayload: "Nope!\nError" });
    return expect(new SimpleFetcher().fetch(uri)).rejects.toThrow(
      "Failed to fetch https://example.com/test/jwks.json: Status code is 500, expected 200"
    );
  });

  test("Simple JSON fetcher uses defaults provided to the constructor", () => {
    const uri = "https://example.com/test/jwks.json";
    const payload = { hello: "world" };
    mockHttpsUri(uri, {
      responsePayload: JSON.stringify(payload),
    });
    expect.assertions(1);
    return expect(
      new SimpleFetcher({
        defaultRequestOptions: { timeout: 100, responseTimeout: 150 },
      }).fetch(uri)
    ).resolves.toEqual(Buffer.from(JSON.stringify(payload)));
  });
});
