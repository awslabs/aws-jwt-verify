import { webcrypto } from "crypto";
import { readFileSync } from "fs";
import { join } from "path";
import { generateKeyPair, signJwt } from "./test-util";
import {
  CloudFrontFunctionOptions,
  MAX_FUNCTION_SIZE,
  assertDeployable,
  cognitoIssuer,
  generateCloudFrontFunction,
} from "../../cloudfront-functions/generate";
import { CognitoJwtVerifier } from "../../src/cognito-verifier";
import { supportedSignatureAlgorithms } from "../../src/jwt-verifier";

const userPoolId = "us-east-1_abcDEF123";
const clientId = "testclientid";
const { issuers } = cognitoIssuer(userPoolId);
const issuer = issuers[0];

type FetchResult = { ok: boolean; status: number; text: () => Promise<string> };

/** Runs the generated function in Node, with fakes for cf.fetch, the KVS and webcrypto */
function loadFunction(
  options: Partial<CloudFrontFunctionOptions>,
  env: {
    kvs?: Record<string, unknown>;
    fetch?: (
      path: string,
      opts: Record<string, unknown>
    ) => Promise<FetchResult>;
  }
) {
  const code = generateCloudFrontFunction({
    userPoolId,
    tokenUse: "access",
    clientId,
    ...options,
  } as CloudFrontFunctionOptions).replace('import cf from "cloudfront";', "");
  const calls: { path: string; opts: Record<string, unknown> }[] = [];
  let cryptoUsed = false;
  const cf = {
    kvs: () => ({
      get: async (key: string, opts: { format: string }) => {
        expect(opts.format).toBe("json");
        if (!env.kvs || !(key in env.kvs)) throw new Error("Key not found");
        // eslint-disable-next-line security/detect-object-injection
        return env.kvs[key];
      },
    }),
    fetch: async (path: string, opts: Record<string, unknown>) => {
      // The runtime allows no network call after webcrypto was used
      if (cryptoUsed) throw new TypeError("call after webcrypto");
      calls.push({ path, opts });
      if (calls.length > 1) throw new TypeError("only one call allowed");
      if (!env.fetch) throw new TypeError("no fetch expected");
      return env.fetch(path, opts);
    },
  };
  const fakeRequire = (name: string) => {
    expect(name).toBe("webcrypto");
    cryptoUsed = true;
    return webcrypto;
  };
  const handler = new Function(
    "cf",
    "require",
    "Buffer",
    `${code}\nreturn handler;`
  )(cf, fakeRequire, Buffer) as (event: unknown) => Promise<any>;
  const invoke = (authorization?: string, extraHeaders = {}) =>
    handler({
      request: {
        method: "GET",
        uri: "/",
        headers: {
          ...extraHeaders,
          ...(authorization !== undefined
            ? { authorization: { value: authorization } }
            : {}),
        },
      },
    });
  return { invoke, calls };
}

const jwksResponse =
  (body: unknown, status = 200) =>
  async () => ({
    ok: status >= 200 && status < 300,
    status,
    text: async () => (typeof body === "string" ? body : JSON.stringify(body)),
  });

describe("unit tests cloudfront function", () => {
  let rsa: ReturnType<typeof generateKeyPair>;
  let ec: ReturnType<typeof generateKeyPair>;
  let other: ReturnType<typeof generateKeyPair>;
  const accessPayload = () => ({
    iss: issuer,
    sub: "user-1",
    token_use: "access",
    client_id: clientId,
  });
  beforeAll(() => {
    rsa = generateKeyPair({ kty: "RSA", alg: "RS256", kid: "rsa1" });
    ec = generateKeyPair({ kty: "EC", alg: "ES256", kid: "ec1" });
    other = generateKeyPair({ kty: "RSA", alg: "RS256", kid: "rsa1" });
  });
  const sign = (payload: object, header: object = { kid: "rsa1" }) =>
    signJwt(header, payload, rsa.privateKey);
  const kvsWithRsa = () => ({ kvs: { "jwk:rsa1": rsa.jwk } });

  describe("generateCloudFrontFunction", () => {
    test("output fits in a CloudFront Function", () => {
      const code = generateCloudFrontFunction({
        userPoolId,
        tokenUse: "access",
        clientId,
      });
      expect(Buffer.byteLength(code)).toBeLessThan(MAX_FUNCTION_SIZE);
      expect(code).not.toMatch(/^\s*\/\//m);
    });
    test("the template itself fits in a CloudFront Function", () => {
      expect(() =>
        assertDeployable(
          readFileSync(
            join(__dirname, "../../cloudfront-functions/jwt-verifier.js"),
            "utf8"
          )
        )
      ).not.toThrow();
    });
    test("Cognito issuers match CognitoJwtVerifier.parseUserPoolId", () => {
      const regional = CognitoJwtVerifier.parseUserPoolId(userPoolId);
      const global = CognitoJwtVerifier.parseUserPoolId(
        userPoolId,
        "https://issuer-cognito-idp.us-east-1.amazonaws.com/x"
      );
      expect(issuers).toEqual([regional.issuer, global.issuer]);
      expect(
        `https://${cognitoIssuer(userPoolId).originDomainName}${cognitoIssuer(userPoolId).jwksPath}`
      ).toBe(regional.jwksUri);
    });
    test("supports a subset of the library's algorithms", () => {
      const code = generateCloudFrontFunction({
        userPoolId,
        tokenUse: "access",
        clientId,
      });
      const algs = Object.keys(
        new Function(
          `${code.match(/const ALGS = \{[^}]+\};/)![0]} return ALGS;`
        )()
      );
      expect(algs.length).toBeGreaterThan(0);
      algs.forEach((alg) =>
        expect(supportedSignatureAlgorithms).toContain(alg)
      );
    });
    test("rejects bad options", () => {
      expect(() =>
        generateCloudFrontFunction({
          userPoolId: "bad",
          tokenUse: "access",
          clientId,
        })
      ).toThrow("Invalid Cognito User Pool ID");
      expect(() => generateCloudFrontFunction({ userPoolId } as any)).toThrow(
        "tokenUse and clientId must be provided"
      );
      expect(() =>
        generateCloudFrontFunction({ issuer: "https://idp" } as any)
      ).toThrow("Provide userPoolId, or issuer and jwksPath");
      expect(() =>
        generateCloudFrontFunction({ issuer: "https://idp", jwksPath: "/j" })
      ).toThrow("audience must be provided");
    });
    test.each([
      ["const a = b?.c;", "optional chaining"],
      ["const a = { ...b };", "spread"],
      ["for (const a of b) {}", "for...of"],
      ["f(await g());", "await inside call arguments"],
      ["x".repeat(MAX_FUNCTION_SIZE + 1), "over"],
    ])("assertDeployable rejects %#", (code, message) => {
      expect(() => assertDeployable(code)).toThrow(message);
    });
  });

  describe("handler", () => {
    test("valid access token, JWK from the KVS: no network call", async () => {
      const { invoke, calls } = loadFunction({}, kvsWithRsa());
      const res = await invoke(`Bearer ${sign(accessPayload())}`);
      expect(res.uri).toBe("/");
      expect(res.headers["x-jwt-sub"]).toEqual({ value: "user-1" });
      expect(res.headers["x-jwt-client-id"]).toEqual({ value: clientId });
      expect(res.headers["x-jwt-jwks"]).toEqual({ value: "kvs" });
      expect(calls).toHaveLength(0);
    });
    test("KVS miss: fetches the JWKS from the issuer origin, once", async () => {
      const { invoke, calls } = loadFunction(
        {},
        { fetch: jwksResponse(rsa.jwks) }
      );
      const res = await invoke(`Bearer ${sign(accessPayload())}`);
      expect(res.headers["x-jwt-jwks"]).toEqual({ value: "fetch" });
      expect(calls).toEqual([
        {
          path: `/${userPoolId}/.well-known/jwks.json`,
          opts: expect.objectContaining({
            originId: "jwt-issuer",
            includeBody: true,
          }),
        },
      ]);
    });
    test("stale KVS entry (other kid): refetches the JWKS", async () => {
      const { invoke, calls } = loadFunction(
        {},
        {
          kvs: { "jwk:rsa1": { ...rsa.jwk, kid: "old" } },
          fetch: jwksResponse(rsa.jwks),
        }
      );
      const res = await invoke(`Bearer ${sign(accessPayload())}`);
      expect(res.headers["x-jwt-jwks"]).toEqual({ value: "fetch" });
      expect(calls).toHaveLength(1);
    });
    test("ES256", async () => {
      const { invoke } = loadFunction({}, { kvs: { "jwk:ec1": ec.jwk } });
      const jwt = signJwt(
        { kid: "ec1", alg: "ES256" },
        accessPayload(),
        ec.privateKey
      );
      const res = await invoke(`Bearer ${jwt}`);
      expect(res.headers["x-jwt-sub"]).toEqual({ value: "user-1" });
    });
    test("id token, tokenUse id: client id from aud", async () => {
      const { invoke } = loadFunction({ tokenUse: "id" }, kvsWithRsa());
      const res = await invoke(
        `Bearer ${sign({ iss: issuer, sub: "u", token_use: "id", aud: clientId })}`
      );
      expect(res.headers["x-jwt-client-id"]).toEqual({ value: clientId });
    });
    test("removes x-jwt-* headers sent by the viewer", async () => {
      const { invoke } = loadFunction({}, kvsWithRsa());
      const res = await invoke(undefined, {
        "x-jwt-sub": { value: "admin" },
      });
      expect(res.statusCode).toBe(401);
      const ok = await invoke(
        `Bearer ${sign({ ...accessPayload(), sub: undefined })}`,
        { "x-jwt-sub": { value: "admin" } }
      );
      expect(ok.headers["x-jwt-sub"]).toBeUndefined();
    });

    const denied: [
      string,
      () => string,
      Partial<CloudFrontFunctionOptions>,
      string,
    ][] = [
      ["no token", () => "", {}, "JwtParseError"],
      ["not a bearer token", () => "Basic abc", {}, "JwtParseError"],
      ["malformed JWT", () => "Bearer a.b", {}, "JwtParseError"],
      [
        "payload not JSON",
        () => "Bearer eyJh.bm90IGpzb24.c2ln",
        {},
        "JwtParseError",
      ],
      [
        "wrong issuer",
        () => `Bearer ${sign({ ...accessPayload(), iss: "https://evil" })}`,
        {},
        "JwtInvalidIssuerError",
      ],
      [
        "no kid",
        () => `Bearer ${sign(accessPayload(), {})}`,
        {},
        "JwtWithoutValidKidError",
      ],
      [
        "expired",
        () =>
          `Bearer ${sign({ ...accessPayload(), exp: Math.floor(Date.now() / 1000) - 10 })}`,
        {},
        "JwtExpiredError",
      ],
      [
        "not yet valid",
        () =>
          `Bearer ${sign({ ...accessPayload(), nbf: Math.floor(Date.now() / 1000) + 60 })}`,
        {},
        "JwtNotBeforeError",
      ],
      [
        "wrong client id",
        () => `Bearer ${sign({ ...accessPayload(), client_id: "other" })}`,
        {},
        "CognitoJwtInvalidClientIdError",
      ],
      [
        "id token where access is required",
        () =>
          `Bearer ${sign({ ...accessPayload(), token_use: "id", aud: clientId })}`,
        {},
        "CognitoJwtInvalidTokenUseError",
      ],
      [
        "unknown token_use",
        () => `Bearer ${sign({ ...accessPayload(), token_use: "refresh" })}`,
        { tokenUse: null },
        "CognitoJwtInvalidTokenUseError",
      ],
      [
        "missing scope",
        () => `Bearer ${sign({ ...accessPayload(), scope: "read" })}`,
        { scope: "write" },
        "JwtInvalidScopeError",
      ],
      [
        "missing group",
        () => `Bearer ${sign({ ...accessPayload(), "cognito:groups": ["a"] })}`,
        { groups: ["b"] },
        "CognitoJwtInvalidGroupError",
      ],
      [
        "forged signature",
        () =>
          `Bearer ${signJwt({ kid: "rsa1" }, accessPayload(), other.privateKey)}`,
        {},
        "JwtInvalidSignatureError",
      ],
      [
        "alg does not match the JWK",
        () => `Bearer ${sign(accessPayload(), { kid: "rsa1", alg: "RS384" })}`,
        {},
        "JwtInvalidSignatureAlgorithmError",
      ],
      [
        "alg none",
        () =>
          `Bearer ${Buffer.from(JSON.stringify({ kid: "rsa1", alg: "none" })).toString("base64url")}.${sign(accessPayload()).split(".").slice(1).join(".")}`,
        {},
        "JwtInvalidSignatureAlgorithmError",
      ],
    ];
    test.each(denied)("401 %s", async (_, token, options, error) => {
      const { invoke, calls } = loadFunction(options, kvsWithRsa());
      const res = await invoke(token() || undefined);
      expect(res.statusCode).toBe(401);
      expect(res.headers["x-jwt-error"]).toEqual({ value: error });
      expect(res.headers["www-authenticate"].value).toMatch(/^Bearer/);
      expect(calls).toHaveLength(0);
    });

    test("tampered payload is an invalid signature", async () => {
      const { invoke } = loadFunction({}, kvsWithRsa());
      const [h, , s] = sign(accessPayload()).split(".");
      const p = Buffer.from(
        JSON.stringify({ ...accessPayload(), sub: "admin" })
      ).toString("base64url");
      const res = await invoke(`Bearer ${h}.${p}.${s}`);
      expect(res.headers["x-jwt-error"]).toEqual({
        value: "JwtInvalidSignatureError",
      });
    });
    test("grace seconds", async () => {
      const { invoke } = loadFunction({ graceSeconds: 60 }, kvsWithRsa());
      const res = await invoke(
        `Bearer ${sign({ ...accessPayload(), exp: Math.floor(Date.now() / 1000) - 10 })}`
      );
      expect(res.statusCode).toBeUndefined();
    });
    test("kid not in the fetched JWKS", async () => {
      const { invoke, calls } = loadFunction(
        {},
        { fetch: jwksResponse(ec.jwks) }
      );
      const res = await invoke(`Bearer ${sign(accessPayload())}`);
      expect(res.statusCode).toBe(401);
      expect(res.headers["x-jwt-error"]).toEqual({
        value: "KidNotFoundInJwksError",
      });
      expect(calls).toHaveLength(1);
    });
    test.each([
      [
        "TimeoutError",
        async () => {
          const e = new Error("timeout");
          e.name = "TimeoutError";
          throw e;
        },
        "JWKS fetch failed: TimeoutError",
      ],
      [
        "TypeError",
        async () => {
          throw new TypeError("OriginDnsError");
        },
        "JWKS fetch failed: TypeError",
      ],
      ["HTTP 500", jwksResponse("oops", 500), "JWKS fetch returned 500"],
      ["not JSON", jwksResponse("<html>"), "Invalid JWKS"],
      ["no keys", jwksResponse({ nokeys: [] }), "Invalid JWKS"],
    ])(
      "fails closed with 503 when the JWKS fetch fails: %s",
      async (_, fetch, message) => {
        const { invoke } = loadFunction({}, { fetch });
        const res = await invoke(`Bearer ${sign(accessPayload())}`);
        expect(res.statusCode).toBe(503);
        expect(res.headers["x-jwt-error"]).toEqual({
          value: `FetchError: ${message}`,
        });
      }
    );

    describe("generic OIDC (jwt verifier)", () => {
      const options = {
        userPoolId: undefined,
        tokenUse: undefined,
        clientId: undefined,
        issuer: "https://idp.example.com",
        jwksPath: "/.well-known/jwks.json",
        audience: ["api"],
      };
      const payload = { iss: "https://idp.example.com", sub: "u", aud: "api" };
      test("valid", async () => {
        const { invoke } = loadFunction(options, kvsWithRsa());
        const res = await invoke(`Bearer ${sign(payload)}`);
        expect(res.headers["x-jwt-client-id"]).toEqual({ value: "api" });
      });
      test("wrong audience", async () => {
        const { invoke } = loadFunction(options, kvsWithRsa());
        const res = await invoke(`Bearer ${sign({ ...payload, aud: ["x"] })}`);
        expect(res.headers["x-jwt-error"]).toEqual({
          value: "JwtInvalidAudienceError",
        });
      });
    });
  });
});
