import {
  generateKeyPair,
  mockHttpsUri,
  signJwt,
  allowAllRealNetworkTraffic,
  disallowAllRealNetworkTraffic,
} from "./test-util";
import { decomposeUnverifiedJwt } from "../../src/jwt";
import {
  JwkInvalidUseError,
  JwkValidationError,
  JwtExpiredError,
  JwtInvalidAudienceError,
  JwtInvalidClaimError,
  JwtInvalidIssuerError,
  JwtInvalidScopeError,
  JwtInvalidSignatureAlgorithmError,
  JwtInvalidSignatureError,
  JwtNotBeforeError,
  JwtParseError,
  JwtWithoutValidKidError,
  KidNotFoundInJwksError,
  ParameterValidationError,
} from "../../src/error";
import {
  JwtVerifier,
  verifyJwt,
  verifyJwtSync,
  KeyObjectCache,
} from "../../src/jwt-verifier";
import { nodeWebCompat } from "../../src/node-web-compat-node";
import { JwksCache, Jwks, Jwk, SignatureJwk } from "../../src/jwk";
import { performance } from "perf_hooks";
import { KeyObject } from "crypto";
import { validateCognitoJwtFields } from "../../src/cognito-verifier";
import { assertStringEquals } from "../../src/assert";

describe("unit tests jwt verifier", () => {
  let keypair: ReturnType<typeof generateKeyPair>;
  beforeAll(() => {
    keypair = generateKeyPair();
    disallowAllRealNetworkTraffic();
  });
  afterAll(() => {
    allowAllRealNetworkTraffic();
  });

  describe("verifySync", () => {
    describe("basic cases", () => {
      test("happy flow with RS256 jwk", () => {
        const issuer = "https://example.com";
        const audience = "1234";
        const signedJwt = signJwt(
          { kid: keypair.jwk.kid },
          { aud: audience, iss: issuer, hello: "world" },
          keypair.privateKey
        );
        expect(
          verifyJwtSync(signedJwt, keypair.jwk, { issuer, audience })
        ).toMatchObject({ hello: "world" });
      });
      test("happy flow with RS384 jwk", () => {
        const rs384keypair = generateKeyPair({ kty: "RSA", alg: "RS384" });
        const issuer = "https://example.com";
        const audience = "1234";
        const signedJwt = signJwt(
          { kid: rs384keypair.jwk.kid, alg: "RS384" },
          { aud: audience, iss: issuer, hello: "world" },
          rs384keypair.privateKey
        );
        expect(
          verifyJwtSync(signedJwt, rs384keypair.jwk, { issuer, audience })
        ).toMatchObject({ hello: "world" });
      });
      test("happy flow with RS512 jwk", () => {
        const rs512keypair = generateKeyPair({ kty: "RSA", alg: "RS512" });
        const issuer = "https://example.com";
        const audience = "1234";
        const signedJwt = signJwt(
          { kid: rs512keypair.jwk.kid, alg: "RS512" },
          { aud: audience, iss: issuer, hello: "world" },
          rs512keypair.privateKey
        );
        expect(
          verifyJwtSync(signedJwt, rs512keypair.jwk, { issuer, audience })
        ).toMatchObject({ hello: "world" });
      });
      test("happy flow with jwk - ES256", () => {
        const es256keypair = generateKeyPair({
          kty: "EC",
          alg: "ES256",
        });
        const issuer = "https://example.com";
        const audience = "1234";
        const signedJwt = signJwt(
          { alg: "ES256", kid: keypair.jwk.kid },
          { aud: audience, iss: issuer, hello: "world" },
          es256keypair.privateKey
        );
        expect(
          verifyJwtSync(signedJwt, es256keypair.jwk, { issuer, audience })
        ).toMatchObject({ hello: "world" });
      });
      test("happy flow with jwk - ES256 padded", () => {
        const es256keypair = generateKeyPair({
          kty: "EC",
          alg: "ES256",
        });
        const issuer = "https://example.com";
        const audience = "1234";
        const signedJwt = signJwt(
          { alg: "ES256", kid: keypair.jwk.kid },
          { aud: audience, iss: issuer, hello: "world" },
          es256keypair.privateKey,
          { addBogusPadding: true }
        );
        expect(
          verifyJwtSync(signedJwt, es256keypair.jwk, { issuer, audience })
        ).toMatchObject({ hello: "world" });
      });
      test("happy flow with jwk - ES384", () => {
        const es384keypair = generateKeyPair({
          kty: "EC",
          alg: "ES384",
        });
        const issuer = "https://example.com";
        const audience = "1234";
        const signedJwt = signJwt(
          { alg: "ES384", kid: keypair.jwk.kid },
          { aud: audience, iss: issuer, hello: "world" },
          es384keypair.privateKey
        );
        expect(
          verifyJwtSync(signedJwt, es384keypair.jwk, { issuer, audience })
        ).toMatchObject({ hello: "world" });
      });
      test("happy flow with jwk - ES512", () => {
        const es512keypair = generateKeyPair({
          kty: "EC",
          alg: "ES512",
        });
        const issuer = "https://example.com";
        const audience = "1234";
        const signedJwt = signJwt(
          { alg: "ES512", kid: keypair.jwk.kid },
          { aud: audience, iss: issuer, hello: "world" },
          es512keypair.privateKey
        );
        expect(
          verifyJwtSync(signedJwt, es512keypair.jwk, { issuer, audience })
        ).toMatchObject({ hello: "world" });
      });
      test("happy flow with jwk - Ed25519", () => {
        const ed25519keypair = generateKeyPair({
          kty: "OKP",
          alg: "EdDSA",
          crv: "Ed25519",
        });
        const issuer = "https://example.com";
        const audience = "1234";
        const signedJwt = signJwt(
          { alg: "EdDSA", kid: keypair.jwk.kid },
          { aud: audience, iss: issuer, hello: "world" },
          ed25519keypair.privateKey
        );
        expect(
          verifyJwtSync(signedJwt, ed25519keypair.jwk, { issuer, audience })
        ).toMatchObject({ hello: "world" });
      });
      test("happy flow with jwk - Ed448", () => {
        const ed448keypair = generateKeyPair({
          kty: "OKP",
          alg: "EdDSA",
          crv: "Ed448",
        });
        const issuer = "https://example.com";
        const audience = "1234";
        const signedJwt = signJwt(
          { alg: "EdDSA", kid: keypair.jwk.kid },
          { aud: audience, iss: issuer, hello: "world" },
          ed448keypair.privateKey
        );
        expect(
          verifyJwtSync(signedJwt, ed448keypair.jwk, { issuer, audience })
        ).toMatchObject({ hello: "world" });
      });
      test("happy flow with jwk without alg", () => {
        const issuer = "https://example.com";
        const audience = "1234";
        const copiedjwk = { ...keypair.jwk };
        delete copiedjwk.alg;
        const signedJwt = signJwt(
          { kid: copiedjwk.kid },
          { aud: audience, iss: issuer, hello: "world" },
          keypair.privateKey
        );
        expect(
          verifyJwtSync(signedJwt, copiedjwk, { issuer, audience })
        ).toMatchObject({ hello: "world" });
      });
      test("happy flow with jwks", () => {
        const issuer = "https://example.com";
        const audience = "1234";
        const signedJwt = signJwt(
          { kid: keypair.jwk.kid },
          { aud: audience, iss: issuer, hello: "world" },
          keypair.privateKey
        );
        expect(
          verifyJwtSync(signedJwt, keypair.jwks, { issuer, audience })
        ).toMatchObject({ hello: "world" });
      });
      test("happy flow with mixed JWKS - JWKS that includes unsupported keys", () => {
        const issuer = "https://example.com";
        const audience = "1234";
        const signedJwt = signJwt(
          { kid: keypair.jwk.kid },
          { aud: audience, iss: issuer, hello: "world" },
          keypair.privateKey
        );
        const mixedJwks: Jwks = {
          keys: [
            {
              kty: "RSA",
              alg: "PS256",
              use: "sig",
              kid: "somekid",
            },
            keypair.jwk,
            {
              kty: "EC",
              alg: "ES256",
              use: "sig",
              hasNoKid: "test",
            },
          ],
        };
        expect(
          verifyJwtSync(signedJwt, mixedJwks, { issuer, audience })
        ).toMatchObject({ hello: "world" });
      });
      test("happy flow JWT with multiple audience values", () => {
        const issuer = "https://example.com";
        const audience = ["1234", "5678"];
        const signedJwt = signJwt(
          { kid: keypair.jwk.kid },
          { aud: audience, iss: issuer, hello: "world" },
          keypair.privateKey
        );
        expect(
          verifyJwtSync(signedJwt, keypair.jwk, {
            issuer,
            audience: ["4321", "5678"],
          })
        ).toMatchObject({ hello: "world" });
      });
      test("happy flow JWT with multiple audience values verified by string", () => {
        const issuer = "https://example.com";
        const audience = ["1234", "5678"];
        const signedJwt = signJwt(
          { kid: keypair.jwk.kid },
          { aud: audience, iss: issuer, hello: "world" },
          keypair.privateKey
        );
        expect(
          verifyJwtSync(signedJwt, keypair.jwk, { issuer, audience: "1234" })
        ).toMatchObject({ hello: "world" });
      });
      test("happy flow with unicode characters in JWT", () => {
        const issuer = "https://example.com";
        const audience = "1234";
        const signedJwt = signJwt(
          { kid: keypair.jwk.kid },
          { aud: audience, iss: issuer, hēłłœ: "wørłd" },
          keypair.privateKey
        );
        expect(
          verifyJwtSync(signedJwt, keypair.jwk, { issuer, audience })
        ).toMatchObject({ hēłłœ: "wørłd" });
      });
      test("error flow with wrong algorithm", () => {
        const issuer = "https://example.com";
        const audience = "1234";
        const signedJwt = signJwt(
          { kid: keypair.jwk.kid, alg: "RS384" },
          { aud: audience, iss: issuer, hello: "world" },
          keypair.privateKey
        );
        const statement = () =>
          verifyJwtSync(signedJwt, keypair.jwk, { issuer, audience });
        expect(statement).toThrow(JwtInvalidSignatureAlgorithmError);
        expect(statement).toThrow(
          "JWT signature algorithm not allowed: RS384. Expected: RS256"
        );
      });
      test("error flow with wrong parameters", () => {
        const issuer = "https://example.com";
        const audience = "1234";
        const signedJwt = signJwt(
          { kid: keypair.jwk.kid },
          { aud: audience, iss: issuer, hello: "world" },
          keypair.privateKey
        );
        const statement = () =>
          verifyJwtSync(signedJwt, "https://jwks-uri/jwks.json" as any, {
            issuer,
            audience,
          });
        expect(statement).toThrow(
          "Expected a valid JWK or JWKS (parsed as JavaScript object"
        );
        expect(statement).toThrow(ParameterValidationError);
      });
      test("error flow: no audience provided", () => {
        const issuer = "https://example.com";
        const audience = "1234";
        const signedJwt = signJwt(
          { kid: keypair.jwk.kid },
          { aud: audience, iss: issuer, hello: "world" },
          keypair.privateKey
        );
        const statement = () =>
          verifyJwtSync(signedJwt, keypair.jwk, {
            issuer,
            audience: undefined as unknown as null,
          });
        expect(statement).toThrow(
          "audience must be provided or set to null explicitly"
        );
        expect(statement).toThrow(ParameterValidationError);
      });
      test("error flow: no issuer provided", () => {
        const issuer = "https://example.com";
        const audience = "1234";
        const signedJwt = signJwt(
          { kid: keypair.jwk.kid },
          { aud: audience, iss: issuer, hello: "world" },
          keypair.privateKey
        );
        const statement = () =>
          verifyJwtSync(signedJwt, keypair.jwk, {
            issuer: undefined as unknown as null,
            audience,
          });
        expect(statement).toThrow(
          "issuer must be provided or set to null explicitly"
        );
        expect(statement).toThrow(ParameterValidationError);
      });
      test("invalid signature", () => {
        const signedJwt = signJwt({}, {}, keypair.privateKey, {
          produceValidSignature: false,
        });
        const statement = () =>
          verifyJwtSync(signedJwt, keypair.jwk, {
            audience: null,
            issuer: null,
          });
        expect(statement).toThrow("Invalid signature");
        expect(statement).toThrow(JwtInvalidSignatureError);
      });
      test("invalid signature - async", async () => {
        const signedJwt = signJwt(
          { kid: keypair.jwk.kid },
          {},
          keypair.privateKey,
          { produceValidSignature: false }
        );
        const statement = () =>
          verifyJwt(signedJwt, "https://example.com/path/to/jwks.json", {
            audience: null,
            issuer: null,
          });
        expect.assertions(2);
        mockHttpsUri("https://example.com/path/to/jwks.json", {
          responsePayload: JSON.stringify(keypair.jwks),
        });
        await expect(statement).rejects.toThrow("Invalid signature");
        mockHttpsUri("https://example.com/path/to/jwks.json", {
          responsePayload: JSON.stringify(keypair.jwks),
        });
        await expect(statement).rejects.toThrow(JwtInvalidSignatureError);
      });
      test("invalid audience", () => {
        const signedJwt = signJwt(
          {},
          { aud: "actualAudience" },
          keypair.privateKey
        );
        const statement = () =>
          verifyJwtSync(signedJwt, keypair.jwk, {
            audience: "expectedAudience",
            issuer: null,
          });
        expect(statement).toThrow(
          "Audience not allowed: actualAudience. Expected: expectedAudience"
        );
        expect(statement).toThrow(JwtInvalidAudienceError);
      });
      test("missing issuer", () => {
        const signedJwt = signJwt({}, {}, keypair.privateKey);
        const statement = () =>
          verifyJwtSync(signedJwt, keypair.jwk, {
            audience: null,
            issuer: "expectedIssuer",
          });
        expect(statement).toThrow("Missing Issuer. Expected: expectedIssuer");
        expect(statement).toThrow(JwtInvalidIssuerError);
      });
    });

    describe("parse errors", () => {
      test("empty JWT", () => {
        const signedJwt: any = undefined;
        const statement = () =>
          verifyJwtSync(signedJwt, keypair.jwk, {
            audience: null,
            issuer: null,
          });
        expect(statement).toThrow("Empty JWT");
        expect(statement).toThrow(JwtParseError);
      });
      test("non-string JWT", () => {
        const signedJwt: any = { foo: "bar" };
        const statement = () =>
          verifyJwtSync(signedJwt, keypair.jwk, {
            audience: null,
            issuer: null,
          });
        expect(statement).toThrow("JWT is not a string");
        expect(statement).toThrow(JwtParseError);
      });
      test("JWT with less than 3 parts", () => {
        const signedJwt = "header.payload";
        const statement = () =>
          verifyJwtSync(signedJwt, keypair.jwk, {
            audience: null,
            issuer: null,
          });
        expect(statement).toThrow(
          "JWT string does not consist of exactly 3 parts (header, payload, signature)"
        );
        expect(statement).toThrow(JwtParseError);
      });
      test("JWT with more than 3 parts", () => {
        const signedJwt = "header.payload.signature.other.garbage";
        const statement = () =>
          verifyJwtSync(signedJwt, keypair.jwk, {
            audience: null,
            issuer: null,
          });
        expect(statement).toThrow(
          "JWT string does not consist of exactly 3 parts (header, payload, signature)"
        );
        expect(statement).toThrow(JwtParseError);
      });
      test("JWT with header that is not JSON parseable", () => {
        const header = Buffer.from("abc").toString("base64url");
        const signedJwt = `${header}.payload.signature`;
        const statement = () =>
          verifyJwtSync(signedJwt, keypair.jwk, {
            audience: null,
            issuer: null,
          });
        expect(statement).toThrow(
          "Invalid JWT. Header is not a valid JSON object"
        );
        expect(statement).toThrow(JwtParseError);
      });
      test("JWT with header that is not an object", () => {
        const header = Buffer.from("123").toString("base64url");
        const signedJwt = `${header}.payload.signature`;
        const statement = () =>
          verifyJwtSync(signedJwt, keypair.jwk, {
            audience: null,
            issuer: null,
          });
        expect(statement).toThrow("JWT header is not an object");
        expect(statement).toThrow(JwtParseError);
      });
      test("JWT with payload that is not JSON parseable", () => {
        const header = Buffer.from('{"alg":"rs256"}').toString("base64url");
        const payload = Buffer.from("abc").toString("base64url");
        const signedJwt = `${header}.${payload}.signature`;
        const statement = () =>
          verifyJwtSync(signedJwt, keypair.jwk, {
            audience: null,
            issuer: null,
          });
        expect(statement).toThrow(
          "Invalid JWT. Payload is not a valid JSON object"
        );
        expect(statement).toThrow(JwtParseError);
      });
      test("JWT with payload that is not an object", () => {
        const header = Buffer.from('{"alg":"rs256"}').toString("base64url");
        const payload = Buffer.from("123").toString("base64url");
        const signedJwt = `${header}.${payload}.signature`;
        const statement = () =>
          verifyJwtSync(signedJwt, keypair.jwk, {
            audience: null,
            issuer: null,
          });
        expect(statement).toThrow("JWT payload is not an object");
        expect(statement).toThrow(JwtParseError);
      });
      test("JWT with alg that is not a string", () => {
        const header = Buffer.from('{"alg":12345}').toString("base64url");
        const payload = Buffer.from('{"iss":"test"}').toString("base64url");
        const signedJwt = `${header}.${payload}.signature`;
        const statement = () =>
          verifyJwtSync(signedJwt, keypair.jwk, {
            audience: null,
            issuer: null,
          });
        expect(statement).toThrow("JWT header alg claim is not a string");
        expect(statement).toThrow(JwtParseError);
      });
      test("JWT alg different from JWK alg", () => {
        const header = Buffer.from('{"alg":"RS512"}').toString("base64url");
        const payload = Buffer.from('{"iss":"test"}').toString("base64url");
        const signedJwt = `${header}.${payload}.signature`;
        const statement = () =>
          verifyJwtSync(signedJwt, keypair.jwk, {
            audience: null,
            issuer: null,
          });
        expect(statement).toThrow(
          "JWT signature algorithm not allowed: RS512. Expected: RS256"
        );
        expect(statement).toThrow(JwtInvalidSignatureAlgorithmError);
      });
      test("JWT with iss that is not a string", () => {
        const header = Buffer.from('{"alg":"RS256"}').toString("base64url");
        const payload = Buffer.from('{"iss":12345}').toString("base64url");
        const signedJwt = `${header}.${payload}.signature`;
        const statement = () =>
          verifyJwtSync(signedJwt, keypair.jwk, {
            audience: null,
            issuer: null,
          });
        expect(statement).toThrow("JWT payload iss claim is not a string");
        expect(statement).toThrow(JwtParseError);
      });
      test("JWT with sub that is not a string", () => {
        const header = Buffer.from('{"alg":"RS256"}').toString("base64url");
        const payload = Buffer.from('{"sub":12345}').toString("base64url");
        const signedJwt = `${header}.${payload}.signature`;
        const statement = () =>
          verifyJwtSync(signedJwt, keypair.jwk, {
            audience: null,
            issuer: null,
          });
        expect(statement).toThrow("JWT payload sub claim is not a string");
        expect(statement).toThrow(JwtParseError);
      });
      test("JWT with aud that is not a string", () => {
        const header = Buffer.from('{"alg":"RS256"}').toString("base64url");
        const payload = Buffer.from('{"aud":12345}').toString("base64url");
        const signedJwt = `${header}.${payload}.signature`;
        const statement = () =>
          verifyJwtSync(signedJwt, keypair.jwk, {
            audience: null,
            issuer: null,
          });
        expect(statement).toThrow("JWT payload aud claim is not a string");
        expect(statement).toThrow(JwtParseError);
      });
      test("JWT with aud that is not a string array", () => {
        const header = Buffer.from('{"alg":"RS256"}').toString("base64url");
        const payload = Buffer.from('{"aud":["1234", 5678]}').toString(
          "base64url"
        );
        const signedJwt = `${header}.${payload}.signature`;
        const statement = () =>
          verifyJwtSync(signedJwt, keypair.jwk, {
            audience: null,
            issuer: null,
          });
        expect(statement).toThrow("JWT payload aud claim is not a string");
        expect(statement).toThrow(JwtParseError);
      });
      test("JWT with iat that is not a number", () => {
        const header = Buffer.from('{"alg":"RS256"}').toString("base64url");
        const payload = Buffer.from('{"iat":"12345"}').toString("base64url");
        const signedJwt = `${header}.${payload}.signature`;
        const statement = () =>
          verifyJwtSync(signedJwt, keypair.jwk, {
            audience: null,
            issuer: null,
          });
        expect(statement).toThrow("JWT payload iat claim is not a number");
        expect(statement).toThrow(JwtParseError);
      });
      test("JWT with scope that is not a string", () => {
        const issuer = "https://example.com";
        const audience = "1234";
        const signedJwt = signJwt(
          { kid: keypair.jwk.kid, alg: "RS512" },
          { aud: audience, iss: issuer, scope: 12345 },
          keypair.privateKey
        );
        const statement = () =>
          verifyJwtSync(signedJwt, keypair.jwk, { issuer, audience });
        expect(statement).toThrow(JwtParseError);
        expect(statement).toThrow("JWT payload scope claim is not a string");
      });
      test("JWT with jti that is not a string", () => {
        const issuer = "https://example.com";
        const audience = "1234";
        const signedJwt = signJwt(
          { kid: keypair.jwk.kid, alg: "RS512" },
          { aud: audience, iss: issuer, scope: "read", jti: 12345 },
          keypair.privateKey
        );
        const statement = () =>
          verifyJwtSync(signedJwt, keypair.jwk, { issuer, audience });
        expect(statement).toThrow(JwtParseError);
        expect(statement).toThrow("JWT payload jti claim is not a string");
      });
    });

    describe("expiry", () => {
      test("expired jwt", () => {
        const exp = new Date();
        const payload = { exp: exp.valueOf() / 1000 };
        const signedJwt = signJwt({}, payload, keypair.privateKey);
        const statement = () =>
          verifyJwtSync(signedJwt, keypair.jwk, {
            audience: null,
            issuer: null,
          });
        expect.assertions(3);
        expect(statement).toThrow(`Token expired at ${exp.toISOString()}`);
        expect(statement).toThrow(JwtExpiredError);
        try {
          statement();
        } catch (err) {
          if (err instanceof JwtInvalidClaimError) {
            expect(err.failedAssertion.actual).toEqual(payload.exp);
          }
        }
      });
      test("jwt with nonsense exp", () => {
        const signedJwt = signJwt({}, { exp: "Garbage" }, keypair.privateKey);
        const statement = () =>
          verifyJwtSync(signedJwt, keypair.jwk, {
            audience: null,
            issuer: null,
          });
        expect(statement).toThrow("JWT payload exp claim is not a number");
        expect(statement).toThrow(JwtParseError);
      });
      test("jwt with empty exp", () => {
        const signedJwt = signJwt({}, { exp: undefined }, keypair.privateKey);
        const statement = () =>
          verifyJwtSync(signedJwt, keypair.jwk, {
            audience: null,
            issuer: null,
          });
        expect(statement).not.toThrow();
      });
      test("just enough graceSeconds", () => {
        const exp = new Date();
        const signedJwt = signJwt(
          {},
          { exp: exp.valueOf() / 1000 - 999, hello: "world" },
          keypair.privateKey
        );
        expect(
          verifyJwtSync(signedJwt, keypair.jwk, {
            audience: null,
            issuer: null,
            graceSeconds: 1000,
          })
        ).toMatchObject({ hello: "world" });
      });
      test("just too little graceSeconds", () => {
        const exp = new Date();
        const signedJwt = signJwt(
          {},
          { exp: exp.valueOf() / 1000 - 1000, hello: "world" },
          keypair.privateKey
        );
        const statement = () =>
          verifyJwtSync(signedJwt, keypair.jwk, {
            audience: null,
            issuer: null,
            graceSeconds: 1000,
          });
        expect(statement).toThrow(JwtExpiredError);
      });
    });

    describe("not before", () => {
      test("not before", () => {
        const nbf = new Date();
        nbf.setTime(nbf.getTime() + 1000 * 100); // Put 100 secs into future
        const signedJwt = signJwt(
          {},
          { nbf: nbf.valueOf() / 1000 },
          keypair.privateKey
        );
        const statement = () =>
          verifyJwtSync(signedJwt, keypair.jwk, {
            audience: null,
            issuer: null,
          });
        expect(statement).toThrow(
          `Token can't be used before ${nbf.toISOString()}`
        );
        expect(statement).toThrow(JwtNotBeforeError);
      });
      test("invalid nbf", () => {
        const nbf = "foobar";
        const signedJwt = signJwt({}, { nbf }, keypair.privateKey);
        const statement = () =>
          verifyJwtSync(signedJwt, keypair.jwk, {
            audience: null,
            issuer: null,
          });
        expect(statement).toThrow("JWT payload nbf claim is not a number");
        expect(statement).toThrow(JwtParseError);
        try {
          statement();
        } catch (err) {
          if (err instanceof JwtInvalidClaimError) {
            expect(err.failedAssertion.actual).toEqual(nbf);
          }
        }
      });
      test("just enough graceSeconds", () => {
        const nbf = new Date();
        nbf.setTime(nbf.getTime() + 1000 * 100); // Put 100 secs into future
        const signedJwt = signJwt(
          {},
          { nbf: nbf.valueOf() / 1000, hello: "world" },
          keypair.privateKey
        );
        expect(
          verifyJwtSync(signedJwt, keypair.jwk, {
            audience: null,
            issuer: null,
            graceSeconds: 100,
          })
        ).toMatchObject({ hello: "world" });
      });
      test("just too little graceSeconds", () => {
        const nbf = new Date();
        nbf.setTime(nbf.getTime() + 1000 * 100); // Put 100 secs into future
        const signedJwt = signJwt(
          {},
          { nbf: nbf.valueOf() / 1000, hello: "world" },
          keypair.privateKey
        );
        const statement = () =>
          verifyJwtSync(signedJwt, keypair.jwk, {
            audience: null,
            issuer: null,
            graceSeconds: 99,
          });
        expect(statement).toThrow(JwtNotBeforeError);
      });
    });

    describe("scope", () => {
      let signedJwt: ReturnType<typeof signJwt>;
      beforeAll(() => {
        signedJwt = signJwt(
          {},
          { "this is a": "scope test", scope: "blah blah2" },
          keypair.privateKey
        );
      });
      test("happy flow allowing 1 scope", () => {
        expect(
          verifyJwtSync(signedJwt, keypair.jwk, {
            audience: null,
            issuer: null,
            scope: "blah",
          })
        ).toMatchObject({ "this is a": "scope test" });
      });
      test("happy flow allowing multiple scopes", () => {
        expect(
          verifyJwtSync(signedJwt, keypair.jwk, {
            audience: null,
            issuer: null,
            scope: ["blah3", "blah2"],
          })
        ).toMatchObject({ "this is a": "scope test" });
      });
      test("happy flow not requiring any scope", () => {
        expect(
          verifyJwtSync(signedJwt, keypair.jwk, {
            audience: null,
            issuer: null,
          })
        ).toMatchObject({ "this is a": "scope test" });
      });
      test("error flow allowing 1 scope", () => {
        const statement = () =>
          verifyJwtSync(signedJwt, keypair.jwk, {
            audience: null,
            issuer: null,
            scope: "blah3",
          });
        expect(statement).toThrow(
          "Scope not allowed: blah, blah2. Expected: blah3"
        );
        expect(statement).toThrow(JwtInvalidScopeError);
        try {
          statement();
        } catch (err) {
          if (err instanceof JwtInvalidClaimError) {
            expect(err.failedAssertion.actual).toEqual(["blah", "blah2"]);
            expect(err.failedAssertion.expected).toEqual("blah3");
          }
        }
      });
      test("error flow allowing mulitple scopes", () => {
        const statement = () =>
          verifyJwtSync(signedJwt, keypair.jwk, {
            audience: null,
            issuer: null,
            scope: ["blah3", "blah4"],
          });
        expect(statement).toThrow(
          "Scope not allowed: blah, blah2. Expected one of: blah3, blah4"
        );
        expect(statement).toThrow(JwtInvalidScopeError);
      });
      test("error flow jwt without scope", () => {
        const jwtWithoutScope = signJwt(
          {},
          { "this is a": "scope test" },
          keypair.privateKey
        );
        const statement = () =>
          verifyJwtSync(jwtWithoutScope, keypair.jwk, {
            audience: null,
            issuer: null,
            scope: "blah3",
          });
        expect(statement).toThrow("Missing Scope. Expected: blah3");
        expect(statement).toThrow(JwtInvalidScopeError);
      });
    });

    describe("kid errors", () => {
      test("kid is not a string", () => {
        const kid: any = { foo: "bar" };
        const signedJwtWithBsKid = signJwt(
          { kid },
          { hello: "world" },
          keypair.privateKey
        );
        const statementWithBSKid = () =>
          verifyJwt(
            signedJwtWithBsKid,
            "https://example.com/does/not/exist/jwks.json",
            {
              issuer: null,
              audience: null,
            }
          );
        expect.assertions(2);
        expect(statementWithBSKid).rejects.toThrow(
          "JWT header kid claim is not a string"
        );
        expect(statementWithBSKid).rejects.toThrow(JwtParseError);
      });

      test("kid not in jwks", () => {
        const signedJwtWithoutKid = signJwt(
          {},
          { hello: "world" },
          keypair.privateKey
        );
        const statementWithoutKid = () =>
          verifyJwtSync(signedJwtWithoutKid, keypair.jwks, {
            issuer: null,
            audience: null,
          });
        expect(statementWithoutKid).toThrow(
          "JWK for kid undefined not found in the JWKS"
        );
        expect(statementWithoutKid).toThrow(KidNotFoundInJwksError);
        const signedJwtWithUnknownKid = signJwt(
          { kid: "abcd" },
          { hello: "world" },
          keypair.privateKey
        );
        const statementWithUnknownKid = () =>
          verifyJwtSync(signedJwtWithUnknownKid, keypair.jwks, {
            issuer: null,
            audience: null,
          });
        expect(statementWithUnknownKid).toThrow(
          "JWK for kid abcd not found in the JWKS"
        );
        expect(statementWithUnknownKid).toThrow(KidNotFoundInJwksError);
      });
    });
    describe("invalid JWK for token verification", () => {
      test("wrong signature algorithm", () => {
        const wrongJwk = { ...keypair.jwk, alg: "RS384" };
        const issuer = "https://example.com";
        const audience = "1234";
        const signedJwt = signJwt(
          { kid: keypair.jwk.kid },
          { aud: audience, iss: issuer, hello: "world" },
          keypair.privateKey
        );
        const statement = () =>
          verifyJwtSync(signedJwt, wrongJwk, { issuer, audience });
        expect(statement).toThrow(
          `JWT signature algorithm not allowed: ${keypair.jwk.alg}. Expected: ${wrongJwk.alg}`
        );
        expect(statement).toThrow(JwtInvalidSignatureAlgorithmError);
      });
      test("unsupported signature algorithm", () => {
        const header = Buffer.from('{"alg":"PS256"}').toString("base64url");
        const payload = Buffer.from(
          '{"iss":"testiss","aud":"testaud"}'
        ).toString("base64url");
        const signedJwt = `${header}.${payload}.signature`;
        const { alg: _, ...jwkWithoutAlg } = keypair.jwk;
        const statementWithJwkWithoutAlg = () =>
          verifyJwtSync(signedJwt, jwkWithoutAlg, {
            audience: "testaud",
            issuer: "testiss",
          });
        expect(statementWithJwkWithoutAlg).toThrow(
          `JWT signature algorithm not allowed: PS256. Expected one of: RS256, RS384, RS512, ES256, ES384, ES512`
        );
        expect(statementWithJwkWithoutAlg).toThrow(
          JwtInvalidSignatureAlgorithmError
        );
        const statementWithJwkWithWrongAlg = () =>
          verifyJwtSync(
            signedJwt,
            { ...jwkWithoutAlg, alg: "PS256" },
            {
              audience: "testaud",
              issuer: "testiss",
            }
          );
        expect(statementWithJwkWithWrongAlg).toThrow(
          `JWT signature algorithm not allowed: PS256. Expected one of: RS256, RS384, RS512, ES256, ES384, ES512`
        );
        expect(statementWithJwkWithWrongAlg).toThrow(
          JwtInvalidSignatureAlgorithmError
        );
      });
      test("missing signature algorithm", () => {
        const issuer = "https://example.com";
        const audience = "1234";
        const signedJwt = signJwt(
          { kid: keypair.jwk.kid, alg: undefined },
          { aud: audience, iss: issuer, hello: "world" },
          keypair.privateKey
        );
        const statement = () =>
          verifyJwtSync(signedJwt, keypair.jwk, { issuer, audience });
        expect(statement).toThrow(
          "Missing JWT signature algorithm. Expected: RS256"
        );
        expect(statement).toThrow(JwtInvalidSignatureAlgorithmError);
      });
      test("wrong JWK use", () => {
        const wrongJwk = { ...keypair.jwk, use: "notsig" };
        const issuer = "https://example.com";
        const audience = "1234";
        const signedJwt = signJwt(
          { kid: keypair.jwk.kid },
          { aud: audience, iss: issuer, hello: "world" },
          keypair.privateKey
        );
        const statement = () =>
          verifyJwtSync(signedJwt, wrongJwk, { issuer, audience });
        expect(statement).toThrow(
          `JWK use not allowed: ${wrongJwk.use}. Expected: sig`
        );
        expect(statement).toThrow(JwkInvalidUseError);
      });
      test("missing JWK use", () => {
        const { jwk, privateKey } = generateKeyPair();
        const signedJwt = signJwt({}, { hello: "world!" }, privateKey);
        delete (jwk as Jwk).use;
        expect(
          verifyJwtSync(signedJwt, jwk, {
            audience: null,
            issuer: null,
          })
        ).toMatchObject({ hello: "world!" });
      });
      test("missing modulus on JWK", () => {
        const { jwk, privateKey } = generateKeyPair();
        const signedJwt = signJwt({}, {}, privateKey);
        delete (jwk as Jwk).n;
        const statement = () =>
          verifyJwtSync(signedJwt, jwk, {
            audience: null,
            issuer: null,
          });
        expect(statement).toThrow("Missing modulus (n)");
        expect(statement).toThrow(JwkValidationError);
      });
      test("missing exponent on JWK", () => {
        const { jwk, privateKey } = generateKeyPair();
        const signedJwt = signJwt({}, {}, privateKey);
        delete (jwk as Jwk).e;
        const statement = () =>
          verifyJwtSync(signedJwt, jwk, {
            audience: null,
            issuer: null,
          });
        expect(statement).toThrow("Missing exponent (e)");
        expect(statement).toThrow(JwkValidationError);
      });
      test("missing crv on JWK", () => {
        const { jwk, privateKey } = generateKeyPair({
          kty: "EC",
          alg: "ES256",
        });
        delete jwk.crv;
        const signedJwt = signJwt({ alg: "ES256" }, {}, privateKey);
        const statement = () =>
          verifyJwtSync(signedJwt, jwk, {
            audience: null,
            issuer: null,
          });
        expect(statement).toThrow("Missing Curve (crv)");
        expect(statement).toThrow(JwkValidationError);
      });
      test("missing crv on JWK - EdDSA", () => {
        const { jwk, privateKey } = generateKeyPair({
          kty: "OKP",
          alg: "EdDSA",
          crv: "Ed25519",
        });
        delete jwk.crv;
        const signedJwt = signJwt({ alg: "EdDSA" }, {}, privateKey);
        const statement = () =>
          verifyJwtSync(signedJwt, jwk, {
            audience: null,
            issuer: null,
          });
        expect(statement).toThrow("Missing Curve (crv)");
        expect(statement).toThrow(JwkValidationError);
      });
      test("missing x on JWK", () => {
        const { jwk, privateKey } = generateKeyPair({
          kty: "EC",
          alg: "ES256",
        });
        delete jwk.x;
        const signedJwt = signJwt({ alg: "ES256" }, {}, privateKey);
        const statement = () =>
          verifyJwtSync(signedJwt, jwk, {
            audience: null,
            issuer: null,
          });
        expect(statement).toThrow("Missing X Coordinate (x)");
        expect(statement).toThrow(JwkValidationError);
      });
      test("missing x on JWK - EdDSA", () => {
        const { jwk, privateKey } = generateKeyPair({
          kty: "OKP",
          alg: "EdDSA",
          crv: "Ed448",
        });
        delete jwk.x;
        const signedJwt = signJwt({ alg: "EdDSA" }, {}, privateKey);
        const statement = () =>
          verifyJwtSync(signedJwt, jwk, {
            audience: null,
            issuer: null,
          });
        expect(statement).toThrow("Missing X Coordinate (x)");
        expect(statement).toThrow(JwkValidationError);
      });
      test("missing y on JWK", () => {
        const { jwk, privateKey } = generateKeyPair({
          kty: "EC",
          alg: "ES384",
        });
        delete jwk.y;
        const signedJwt = signJwt({ alg: "ES256" }, {}, privateKey);
        const statement = () =>
          verifyJwtSync(signedJwt, jwk, {
            audience: null,
            issuer: null,
          });
        expect(statement).toThrow("Missing Y Coordinate (y)");
        expect(statement).toThrow(JwkValidationError);
      });
    });
    describe("includeJwtInErrors", () => {
      test("expired jwt with flag set", () => {
        const exp = new Date();
        const header = { alg: "RS256", kid: keypair.jwk.kid };
        const payload = { hello: "world", exp: exp.valueOf() / 1000 };
        const signedJwt = signJwt(header, payload, keypair.privateKey);
        const statement = () =>
          verifyJwtSync(signedJwt, keypair.jwk, {
            audience: null,
            issuer: null,
            includeRawJwtInErrors: true,
          });
        expect.assertions(2);
        expect(statement).toThrow(JwtExpiredError);
        try {
          statement();
        } catch (err) {
          expect((err as JwtInvalidClaimError).rawJwt).toMatchObject({
            header,
            payload,
          });
        }
      });
      test("not included if flag not set", () => {
        const signedJwt = signJwt({}, {}, keypair.privateKey, {
          produceValidSignature: false,
        });
        const statement = () =>
          verifyJwtSync(signedJwt, keypair.jwk, {
            audience: null,
            issuer: null,
          });
        expect.assertions(1);
        try {
          statement();
        } catch (err) {
          expect((err as JwtInvalidClaimError).rawJwt).toBe(undefined);
        }
      });
      test("not included if flag set to false", () => {
        const signedJwt = signJwt({}, {}, keypair.privateKey, {
          produceValidSignature: false,
        });
        const statement = () =>
          verifyJwtSync(signedJwt, keypair.jwk, {
            audience: null,
            issuer: null,
            includeRawJwtInErrors: false,
          });
        expect.assertions(1);
        try {
          statement();
        } catch (err) {
          expect((err as JwtInvalidClaimError).rawJwt).toBe(undefined);
        }
      });
      test("never included on invalid signature", () => {
        const signedJwt = signJwt({}, {}, keypair.privateKey, {
          produceValidSignature: false,
        });
        const statement = () =>
          verifyJwtSync(signedJwt, keypair.jwk, {
            audience: null,
            issuer: null,
            includeRawJwtInErrors: true,
          });
        expect.assertions(1);
        try {
          statement();
        } catch (err) {
          expect((err as JwtInvalidClaimError).rawJwt).toBe(undefined);
        }
      });
      test("included on custom errors too if subclassed from FailedAssertionError", () => {
        class CustomError extends JwtInvalidClaimError {}
        const header = { alg: "RS256", kid: keypair.jwk.kid };
        const payload = { hello: "world" };
        const signedJwt = signJwt(header, payload, keypair.privateKey);
        const statement = () =>
          verifyJwtSync(signedJwt, keypair.jwk, {
            audience: null,
            issuer: null,
            includeRawJwtInErrors: true,
            customJwtCheck: () => {
              throw new CustomError("Oops", "actualValue");
            },
          });
        expect.assertions(2);
        expect(statement).toThrow(CustomError);
        try {
          statement();
        } catch (err) {
          expect((err as CustomError).rawJwt).toMatchObject({
            header,
            payload,
          });
        }
      });
    });
  });

  describe("verify", () => {
    test("happy flow - RS256", () => {
      const issuer = "https://example.com";
      const audience = "1234";
      const signedJwt = signJwt(
        { kid: keypair.jwk.kid },
        { aud: audience, iss: issuer, hello: "world" },
        keypair.privateKey
      );
      mockHttpsUri("https://example.com/path/to/jwks.json", {
        responsePayload: JSON.stringify(keypair.jwks),
      });
      expect.assertions(1);
      return expect(
        verifyJwt(signedJwt, "https://example.com/path/to/jwks.json", {
          issuer,
          audience,
        })
      ).resolves.toMatchObject({ hello: "world" });
    });
    test("happy flow - ES256", () => {
      const es256keypair = generateKeyPair({
        kty: "EC",
        alg: "ES256",
      });
      const issuer = "https://example.com";
      const audience = "1234";
      const signedJwt = signJwt(
        { alg: "ES256", kid: keypair.jwk.kid },
        { aud: audience, iss: issuer, hello: "world" },
        es256keypair.privateKey
      );
      mockHttpsUri("https://example.com/path/to/jwks.json", {
        responsePayload: JSON.stringify(es256keypair.jwks),
      });
      expect.assertions(1);
      return expect(
        verifyJwt(signedJwt, "https://example.com/path/to/jwks.json", {
          issuer,
          audience,
        })
      ).resolves.toMatchObject({ hello: "world" });
    });
    describe("includeJwtInErrors", () => {
      test("expired jwt and includeRawJwtInErrors", async () => {
        const exp = new Date();
        const header = { alg: "RS256", kid: keypair.jwk.kid };
        const payload = { hello: "world", exp: exp.valueOf() / 1000 };
        const signedJwt = signJwt(header, payload, keypair.privateKey);
        mockHttpsUri("https://example.com/some/path/to/jwks.json", {
          responsePayload: JSON.stringify(keypair.jwks),
        });
        const statement = () =>
          verifyJwt(signedJwt, "https://example.com/some/path/to/jwks.json", {
            audience: null,
            issuer: null,
            includeRawJwtInErrors: true,
          });
        expect.assertions(2);
        return statement().catch((err) => {
          expect(err).toBeInstanceOf(JwtExpiredError);
          expect((err as JwtInvalidClaimError).rawJwt).toEqual({
            header,
            payload,
          });
        });
      });
      test("expired jwt and NOT includeRawJwtInErrors", async () => {
        const exp = Date.now() / 1000; // expires NOW
        const header = { alg: "RS256", kid: keypair.jwk.kid };
        const payload = { hello: "world", exp };
        const signedJwt = signJwt(header, payload, keypair.privateKey);
        mockHttpsUri("https://example.com/some/path/to/jwks.json", {
          responsePayload: JSON.stringify(keypair.jwks),
        });
        const statement = () =>
          verifyJwt(signedJwt, "https://example.com/some/path/to/jwks.json", {
            audience: null,
            issuer: null,
          });
        expect.assertions(2);
        return statement().catch((err) => {
          expect(err).toBeInstanceOf(JwtExpiredError);
          expect((err as JwtInvalidClaimError).rawJwt).toBe(undefined);
        });
      });
      test("included on custom errors too if subclassed from FailedAssertionError", async () => {
        class CustomError extends JwtInvalidClaimError {}
        const header = { alg: "RS256", kid: keypair.jwk.kid };
        const exp = Date.now() / 1000 + 10; // Expires in 10 secs
        const payload = { hello: "world", exp };
        const signedJwt = signJwt(header, payload, keypair.privateKey);
        mockHttpsUri("https://example.com/some/path/to/jwks.json", {
          responsePayload: JSON.stringify(keypair.jwks),
        });
        const statement = () =>
          verifyJwt(signedJwt, "https://example.com/some/path/to/jwks.json", {
            audience: null,
            issuer: null,
            includeRawJwtInErrors: true,
            customJwtCheck: () => {
              throw new CustomError("Oops", "actualValue");
            },
          });
        expect.assertions(2);
        try {
          await statement();
        } catch (err) {
          expect(err).toBeInstanceOf(CustomError);
          expect((err as CustomError).rawJwt).toEqual({
            header,
            payload,
          });
        }
      });
    });
  });

  describe("JwtVerifier", () => {
    describe("verify", () => {
      test("happy flow", () => {
        const issuer = "https://example.com";
        const verifier = JwtVerifier.create({
          issuer,
          jwksUri: `${issuer}/.well-known/keys.json`,
          customJwtCheck: async () => {
            await new Promise((resolve) => setImmediate(resolve, null));
          },
        });
        verifier.cacheJwks(keypair.jwks);
        const signedJwt = signJwt(
          { kid: keypair.jwk.kid },
          { aud: "1234", iss: issuer, hello: "world" },
          keypair.privateKey
        );
        expect.assertions(1);
        return expect(
          verifier.verify(signedJwt, { audience: ["123", "1234"] })
        ).resolves.toMatchObject({ hello: "world" });
      });
      test("happy flow - jwks uri defaults from issuer", () => {
        const issuer = "https://example.com/foo/bar";
        const verifier = JwtVerifier.create({
          issuer,
        });
        mockHttpsUri(`${issuer}/.well-known/jwks.json`, {
          responsePayload: JSON.stringify(keypair.jwks),
        });
        const signedJwt = signJwt(
          { kid: keypair.jwk.kid },
          { aud: "1234", iss: issuer, hello: "world" },
          keypair.privateKey
        );
        expect.assertions(1);
        return expect(
          verifier.verify(signedJwt, { audience: ["123", "1234"] })
        ).resolves.toMatchObject({ hello: "world" });
      });
      test("jwt without iss claim - verifier has issuer null", () => {
        const signedJwt = signJwt(
          { kid: keypair.jwk.kid },
          { hello: "world", aud: "1234567890" },
          keypair.privateKey
        );
        const verifier = JwtVerifier.create({
          issuer: null,
          jwksUri: "https://example.com/keys/jwks.json",
          audience: "1234567890",
        });
        verifier.cacheJwks(keypair.jwks);
        expect.assertions(1);
        expect(verifier.verify(signedJwt)).resolves.toMatchObject({
          hello: "world",
        });
      });
      test("jwt with iss claim - verifier has issuer null", () => {
        const issuer = "https://example.com/foo/bar";
        const signedJwt = signJwt(
          { kid: keypair.jwk.kid },
          { hello: "world", iss: issuer, aud: "1234567890" },
          keypair.privateKey
        );
        const verifier = JwtVerifier.create({
          issuer: null,
          jwksUri: "https://example.com/keys/jwks.json",
          audience: "1234567890",
        });
        verifier.cacheJwks(keypair.jwks);
        expect.assertions(1);
        expect(verifier.verify(signedJwt)).resolves.toMatchObject({
          hello: "world",
        });
      });
      test("jwt with iss claim - multi verifier has issuer null", () => {
        const statement = () =>
          JwtVerifier.create([
            {
              issuer: "issuer",
              jwksUri: "https://example.com/keys/jwks.json",
              audience: "1234567890",
            },
            {
              issuer: null as unknown as string,
              jwksUri: "https://example.com/keys/jwks.json",
              audience: "1234567890",
            },
          ]);
        expect(statement).toThrow(ParameterValidationError);
        expect(statement).toThrow(
          "issuer cannot be null when multiple issuers are supplied (at issuer: 1)"
        );
      });

      test("custom JWKS cache", () => {
        class CustomJwksCache implements JwksCache {
          getJwks = jest
            .fn()
            .mockImplementation(async (_jwksUri?: string) => keypair.jwks);
          addJwks = jest
            .fn()
            .mockImplementation((_jwksUri: string, _jwks: Jwks) => {
              // This is intentional
            });
          getCachedJwk = jest
            .fn()
            .mockImplementation(
              (_jwksUri: string, _kid: string) => keypair.jwk
            );
          getJwk = jest
            .fn()
            .mockImplementation(
              async (_jwksUri: string, _kid: string) => keypair.jwk
            );
        }
        const customJwksCache = new CustomJwksCache();
        const issuer = "https://example.com";
        const jwksUri = `${issuer}/.well-known/keys.json`;
        const verifier = JwtVerifier.create(
          {
            issuer,
            jwksUri,
          },
          { jwksCache: customJwksCache }
        );
        verifier.cacheJwks(keypair.jwks);
        expect(customJwksCache.addJwks).toHaveBeenCalledWith(
          jwksUri,
          keypair.jwks
        );
        const signedJwt = signJwt(
          { kid: keypair.jwk.kid },
          { aud: "1234", iss: issuer, hello: "world" },
          keypair.privateKey
        );
        const decomposedJwt = decomposeUnverifiedJwt(signedJwt);
        verifier.verify(signedJwt, { audience: "1234" }).catch(() => {
          // This is intentional
        }); // The sync portion of this async function should call getJwk
        expect(customJwksCache.getJwk).toHaveBeenCalledWith(
          jwksUri,
          decomposedJwt
        );
        verifier.verifySync(signedJwt, { audience: "1234" });
        expect(customJwksCache.getCachedJwk).toHaveBeenCalledWith(
          jwksUri,
          decomposedJwt
        );
        expect.assertions(3);
      });
      test("hydrate the JWKS cache by prefetching JWKS works", async () => {
        const issuer = "https://example.com";
        const verifier = JwtVerifier.create({
          issuer,
        });
        const jwksUri = `${issuer}/.well-known/jwks.json`;
        mockHttpsUri(jwksUri, {
          responsePayload: JSON.stringify(keypair.jwks),
        });
        await verifier.hydrate();
        const audience = "myappclient";
        const signedJwt = signJwt(
          { kid: keypair.jwk.kid },
          { aud: audience, iss: issuer, hello: "world" },
          keypair.privateKey
        );
        verifier.verifySync(signedJwt, { audience }); // should NOT throw, as the JWKS is cached, so sync verify is allowed
      });
      test("hydrate the JWKS cache by prefetching JWKS works - for multiple issuers", async () => {
        const issuer1 = "https://example.com/idp1";
        const issuer2 = "https://example.com/idp2/";
        const issuer3 = "https://example.com/";
        class CustomJwksCache implements JwksCache {
          getJwks = jest
            .fn()
            .mockImplementation(async (_jwksUri?: string) => keypair.jwks);
          addJwks = jest
            .fn()
            .mockImplementation((_jwksUri: string, _jwks: Jwks) => {
              // This is intentional
            });
          getCachedJwk = jest
            .fn()
            .mockImplementation(
              (_jwksUri: string, _kid: string) => keypair.jwk
            );
          getJwk = jest
            .fn()
            .mockImplementation(
              async (_jwksUri: string, _kid: string) => keypair.jwk
            );
        }
        const customJwksCache = new CustomJwksCache();
        const verifier = JwtVerifier.create(
          [
            {
              issuer: issuer1,
              audience: "myappclient1",
            },
            {
              issuer: issuer2,
              audience: "myappclient2",
            },
            {
              issuer: issuer3,
              audience: "myappclient3",
            },
          ],
          {
            jwksCache: customJwksCache,
          }
        );
        await verifier.hydrate();
        expect(customJwksCache.getJwks).toHaveBeenCalledTimes(3);
        expect(customJwksCache.getJwks).toHaveBeenNthCalledWith(
          1,
          "https://example.com/idp1/.well-known/jwks.json"
        );
        expect(customJwksCache.getJwks).toHaveBeenNthCalledWith(
          2,
          "https://example.com/idp2/.well-known/jwks.json"
        );
        expect(customJwksCache.getJwks).toHaveBeenNthCalledWith(
          3,
          "https://example.com/.well-known/jwks.json"
        );
        const audience = "myappclient1";
        const signedJwt = signJwt(
          { kid: keypair.jwk.kid },
          { aud: audience, iss: issuer1, hello: "world" },
          keypair.privateKey
        );
        verifier.verifySync(signedJwt); // should NOT throw, as the JWKS is cached, so sync verify is allowed
      });
      test("custom JWT check that throws", () => {
        const issuer = "https://example.com";
        const verifier = JwtVerifier.create({
          issuer,
          jwksUri: `${issuer}/.well-known/keys.json`,
          customJwtCheck: async () => {
            await new Promise((_, reject) =>
              setImmediate(() =>
                reject(new Error("Oops my custom check failed"))
              )
            );
          },
        });
        verifier.cacheJwks(keypair.jwks);
        const signedJwt = signJwt(
          { kid: keypair.jwk.kid },
          { aud: "1234", iss: issuer, hello: "world" },
          keypair.privateKey
        );
        expect.assertions(1);
        return expect(
          verifier.verify(signedJwt, { audience: ["123", "1234"] })
        ).rejects.toThrow("Oops my custom check failed");
      });
      test("custom JWT check that does not throw", async () => {
        const issuer = "testissuer";
        const audience = "1234";
        const signedJwt = signJwt(
          { kid: keypair.jwk.kid },
          { aud: audience, iss: issuer, hello: "world" },
          keypair.privateKey
        );
        const decomposedJwt = decomposeUnverifiedJwt(signedJwt);
        const customJwtCheck = jest.fn();
        const verifier = JwtVerifier.create({
          issuer,
          jwksUri: "https://example.com/keys/jwks.json",
          audience,
          customJwtCheck,
        });
        verifier.cacheJwks(keypair.jwks);
        expect.assertions(2);
        expect(
          await verifier.verify(signedJwt, { audience: null })
        ).toMatchObject({ hello: "world" });
        expect(customJwtCheck).toHaveBeenCalledWith({
          header: decomposedJwt.header,
          payload: decomposedJwt.payload,
          jwk: keypair.jwk,
        });
      });
    });
    describe("verifySync", () => {
      test("happy flow", () => {
        const issuer = "https://example.com";
        const verifier = JwtVerifier.create({
          issuer,
          jwksUri: `${issuer}/.well-known/keys.json`,
          customJwtCheck: () => {
            // This is intentional
          },
        });
        verifier.cacheJwks(keypair.jwks);
        const signedJwt = signJwt(
          { kid: keypair.jwk.kid },
          { aud: "1234", iss: issuer, hello: "world" },
          keypair.privateKey
        );
        expect(
          verifier.verifySync(signedJwt, { audience: null })
        ).toMatchObject({ hello: "world" });
      });
      test("jwt without iss claim", () => {
        const signedJwt = signJwt(
          { kid: keypair.jwk.kid },
          { hello: "world" },
          keypair.privateKey
        );
        const verifier = JwtVerifier.create({
          issuer: "testissuer",
          jwksUri: "https://example.com/keys/jwks.json",
          audience: "1234567890",
        });
        verifier.cacheJwks(keypair.jwks);
        const statement = () => verifier.verifySync(signedJwt);
        expect(statement).toThrow("iss");
        expect(statement).toThrow(JwtInvalidIssuerError);
      });
      test("jwt without kid claim", () => {
        const signedJwt = signJwt(
          {},
          { hello: "world", iss: "testissuer" },
          keypair.privateKey
        );
        const verifier = JwtVerifier.create({
          issuer: "testissuer",
          jwksUri: "https://example.com/keys/jwks.json",
          audience: "1234567890",
        });
        verifier.cacheJwks(keypair.jwks);
        const statement = () => verifier.verifySync(signedJwt);
        expect(statement).toThrow(JwtWithoutValidKidError);
        expect(statement).toThrow("kid");
      });
      test("custom JWT check for JWT typ: it's the right typ", () => {
        const issuer = "testissuer";
        const audience = "1234";
        const signedJwt = signJwt(
          { kid: keypair.jwk.kid, typ: "Expected JWT typ" },
          { aud: audience, iss: issuer, hello: "world" },
          keypair.privateKey
        );
        const decomposedJwt = decomposeUnverifiedJwt(signedJwt);
        const customJwtCheck = jest.fn().mockImplementation((jwt) => {
          if (jwt.header.typ !== "Expected JWT typ") {
            throw new Error("Oops my custom check failed");
          }
        });
        const verifier = JwtVerifier.create({
          issuer,
          jwksUri: "https://example.com/keys/jwks.json",
          audience,
          customJwtCheck,
        });
        verifier.cacheJwks(keypair.jwks);
        expect.assertions(2);
        expect(
          verifier.verifySync(signedJwt, { audience: null })
        ).toMatchObject({ hello: "world" });
        expect(customJwtCheck).toHaveBeenCalledWith({
          header: decomposedJwt.header,
          payload: decomposedJwt.payload,
          jwk: keypair.jwk,
        });
      });
      test("custom JWT check for JWT typ: not the right typ", () => {
        const issuer = "testissuer";
        const audience = "1234";
        const signedJwt = signJwt(
          { kid: keypair.jwk.kid, typ: "Wrong JWT typ" },
          { aud: audience, iss: issuer, hello: "world" },
          keypair.privateKey
        );
        const verifier = JwtVerifier.create({
          issuer,
          jwksUri: "https://example.com/keys/jwks.json",
          audience,
          customJwtCheck: (jwt) => {
            if (jwt.header.typ !== "Expected JWT typ") {
              throw new Error("Oops my custom check failed");
            }
          },
        });
        verifier.cacheJwks(keypair.jwks);
        const statement = () => verifier.verifySync(signedJwt);
        expect(statement).toThrow("Oops my custom check failed");
      });
      test("custom JWT check that returns a promise", () => {
        const issuer = "testissuer";
        const audience = "1234";
        const signedJwt = signJwt(
          { kid: keypair.jwk.kid },
          { aud: audience, iss: issuer, hello: "world" },
          keypair.privateKey
        );
        const verifier = JwtVerifier.create({
          issuer,
          jwksUri: "https://example.com/keys/jwks.json",
          audience,
          customJwtCheck: async () => {
            "Oops I shouldn't use an async check with verifySync";
          },
        });
        verifier.cacheJwks(keypair.jwks);
        const statement = () => verifier.verifySync(signedJwt);
        expect(statement).toThrow(ParameterValidationError);
        expect(statement).toThrow(
          "Custom JWT checks must be synchronous but a promise was returned"
        );
      });
      test("issuer is null - non-standard iss field", () => {
        const verifier = JwtVerifier.create({
          issuer: null,
          audience: null,
          jwksUri: "https://example.com/keys/jwks.json",
          customJwtCheck: ({ payload }) => {
            assertStringEquals(
              "Issuer",
              payload.myIssFieldWithWeirdName,
              "my issuer"
            );
          },
        });
        verifier.cacheJwks(keypair.jwks);
        const signedJwt = signJwt(
          { kid: keypair.jwk.kid },
          {
            hello: "world",
            myIssFieldWithWeirdName: "my issuer",
          },
          keypair.privateKey
        );
        expect(verifier.verifySync(signedJwt)).toMatchObject({
          hello: "world",
        });
      });
      test("issuer is null - no JWKS uri", () => {
        const statement = () =>
          JwtVerifier.create({
            issuer: null,
            audience: null,
          });
        expect(statement).toThrow(ParameterValidationError);
        expect(statement).toThrow("jwksUri must be provided for issuer null");
      });
    });
  });

  describe("JwtVerifier with mutiple IDPs", () => {
    describe("verify", () => {
      test("happy flow", () => {
        const identityProviders = [
          {
            config: {
              issuer: "https://example.com",
              audience: "myappid",
              jwksUri: "https://example.com/keys/jwks.json",
            },
            keypair: generateKeyPair(),
          },
          {
            config: {
              issuer: "https://example-2.com",
              audience: "myappid-2",
              jwksUri: "https://example-2.com/keys/jwks.json",
            },
            keypair: generateKeyPair(),
          },
        ];
        const verifier = JwtVerifier.create(
          identityProviders.map((idp) => idp.config)
        );

        expect.assertions(identityProviders.length);
        for (const idp of identityProviders) {
          verifier.cacheJwks(idp.keypair.jwks, idp.config.issuer);
          const signedJwt = signJwt(
            { kid: keypair.jwk.kid },
            {
              aud: idp.config.audience,
              iss: idp.config.issuer,
              hello: "world",
            },
            idp.keypair.privateKey
          );
          expect(verifier.verify(signedJwt)).resolves.toMatchObject({
            hello: "world",
          });
        }
      });
      test("cache jwks with multiple IDPs needs issuer", () => {
        const identityProviders = [
          {
            issuer: "https://example.com",
            audience: "audience1",
          },
          {
            issuer: "https://example-2.com",
            audience: "audience2",
          },
        ];
        const verifier = JwtVerifier.create(identityProviders);
        const emptyIssuer: any = undefined;
        const statement = () => verifier.cacheJwks(keypair.jwks, emptyIssuer);
        expect(statement).toThrow("issuer must be provided");
        expect(statement).toThrow(ParameterValidationError);
      });
      test("cache jwks with multiple IDPs needs configured issuer", () => {
        const identityProviders = [
          {
            issuer: "https://example.com",
            audience: "audience1",
          },
          {
            issuer: "https://example-2.com",
            audience: "audience2",
          },
        ];
        const verifier = JwtVerifier.create(identityProviders);
        const statement = () =>
          verifier.cacheJwks(keypair.jwks, "https://example-3.com");
        expect(statement).toThrow("issuer not configured");
        expect(statement).toThrow(ParameterValidationError);
      });
      test("need at least one issuer config", () => {
        const statement = () => JwtVerifier.create([]);
        expect(statement).toThrow("Provide at least one issuer configuration");
        expect(statement).toThrow(ParameterValidationError);
      });
      test("should provide distinct issuers", () => {
        const issuer = "https://example.com";
        const statement = () =>
          JwtVerifier.create([
            {
              issuer,
              audience: "audience1",
            },
            {
              issuer,
              audience: "audience2",
            },
          ]);
        expect(statement).toThrow(`issuer ${issuer} supplied multiple times`);
        expect(statement).toThrow(ParameterValidationError);
      });
    });
  });

  describe("JwtVerifier used for Cognito tokens", () => {
    test("verify access token", () => {
      const poolId = "eu-west-1_poolid";
      const issuer = `https://cognito-idp.eu-west-1.amazonaws.com/${poolId}`;
      const clientId = "<client_id>";
      const verifier = JwtVerifier.create({
        issuer: "https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_poolid",
        audience: null,
        customJwtCheck: ({ payload }) =>
          validateCognitoJwtFields(payload, {
            groups: ["admin", "others"],
            tokenUse: "access",
            clientId,
          }),
      });
      const payload = {
        client_id: clientId,
        token_use: "access",
        "cognito:groups": ["others"],
        iss: issuer,
      };
      const jwt = signJwt(
        { kid: keypair.jwk.kid, alg: "RS256" },
        payload,
        keypair.privateKey
      );
      mockHttpsUri(
        "https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_poolid/.well-known/jwks.json",
        {
          responseStatus: 200,
          responseHeaders: {
            "Content-Type": "application/json",
          },
          responsePayload: JSON.stringify(keypair.jwks),
        }
      );
      return expect(verifier.verify(jwt)).resolves.toMatchObject(payload);
    });
    test("verify id token", () => {
      const poolId = "eu-west-1_poolid";
      const issuer = `https://cognito-idp.eu-west-1.amazonaws.com/${poolId}`;
      const clientId = "<client_id>";
      const verifier = JwtVerifier.create({
        issuer: "https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_poolid",
        audience: null,
        customJwtCheck: ({ payload }) =>
          validateCognitoJwtFields(payload, {
            groups: ["admin", "others"],
            tokenUse: "id",
            clientId,
          }),
      });
      const payload = {
        aud: clientId,
        token_use: "id",
        "cognito:groups": ["admin"],
        iss: issuer,
      };
      const jwt = signJwt(
        { kid: keypair.jwk.kid, alg: "RS256" },
        payload,
        keypair.privateKey
      );
      mockHttpsUri(
        "https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_poolid/.well-known/jwks.json",
        {
          responseStatus: 200,
          responseHeaders: {
            "Content-Type": "application/json",
          },
          responsePayload: JSON.stringify(keypair.jwks),
        }
      );
      return expect(verifier.verify(jwt)).resolves.toMatchObject(payload);
    });
    test("error flow: receive access token but id token expected", () => {
      const poolId = "eu-west-1_poolid";
      const issuer = `https://cognito-idp.eu-west-1.amazonaws.com/${poolId}`;
      const clientId = "<client_id>";
      const verifier = JwtVerifier.create({
        issuer: "https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_poolid",
        audience: null,
        customJwtCheck: ({ payload }) =>
          validateCognitoJwtFields(payload, {
            groups: ["admin", "others"],
            tokenUse: "id",
            clientId,
          }),
      });
      const payload = {
        client_id: clientId,
        token_use: "access",
        "cognito:groups": ["others"],
        iss: issuer,
      };
      const jwt = signJwt(
        { kid: keypair.jwk.kid, alg: "RS256" },
        payload,
        keypair.privateKey
      );
      mockHttpsUri(
        "https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_poolid/.well-known/jwks.json",
        {
          responseStatus: 200,
          responseHeaders: {
            "Content-Type": "application/json",
          },
          responsePayload: JSON.stringify(keypair.jwks),
        }
      );
      return expect(verifier.verify(jwt)).rejects.toThrow(
        "Token use not allowed: access. Expected: id"
      );
    });
  });

  describe("public key cache", () => {
    test("happy flow with cache", () => {
      const jwkToKeyObjectTransformerSpy = jest.fn(
        nodeWebCompat.transformJwkToKeyObjectSync
      );
      const pubkeyCache = new KeyObjectCache(jwkToKeyObjectTransformerSpy);
      const issuer = "testissuer";
      const jwk = keypair.jwk as SignatureJwk;
      const pubkey = pubkeyCache.transformJwkToKeyObjectSync(
        jwk,
        "RS256",
        issuer
      ) as KeyObject;
      expect(pubkey.export({ format: "der", type: "spki" })).toEqual(
        keypair.publicKeyDer
      );
      pubkeyCache.transformJwkToKeyObjectSync(jwk, "RS256", "testissuer"); // same JWK, same issuer, transform from cache
      pubkeyCache.transformJwkToKeyObjectSync(jwk, "RS256", "othertestissuer");
      // Using a different JWK (with other kid) forces the transformer to run
      expect(jwkToKeyObjectTransformerSpy).toHaveBeenCalledTimes(2);
      const otherKeyPair = generateKeyPair({ kty: "RSA", kid: "otherkid" });
      const otherJwk = otherKeyPair.jwk as SignatureJwk;
      pubkeyCache.transformJwkToKeyObjectSync(otherJwk, "RS256", "testissuer");
      pubkeyCache.transformJwkToKeyObjectSync(otherJwk, "RS256", "testissuer"); // same JWK, same issuer, transform from cache
      pubkeyCache.transformJwkToKeyObjectSync(
        otherJwk,
        "RS256",
        "othertestissuer"
      );
      expect(jwkToKeyObjectTransformerSpy).toHaveBeenCalledTimes(4);
      pubkeyCache.clearCache(issuer);
      pubkeyCache.transformJwkToKeyObjectSync(otherJwk, "RS256", "testissuer"); // Cache is empty, so must be regenerated
      expect(jwkToKeyObjectTransformerSpy).toHaveBeenCalledTimes(5);
    });
    test("jwk without alg", () => {
      const issuer = "testissuer";
      const jwkToKeyObjectTransformerSpy = jest.fn(
        nodeWebCompat.transformJwkToKeyObjectSync
      );
      const pubkeyCache = new KeyObjectCache(jwkToKeyObjectTransformerSpy);
      const copiedJwk = { ...(keypair.jwk as SignatureJwk) };
      delete copiedJwk.alg;
      const pubkey = pubkeyCache.transformJwkToKeyObjectSync(
        copiedJwk,
        "RS512",
        issuer
      ) as KeyObject;
      expect(pubkey.export({ format: "der", type: "spki" })).toEqual(
        keypair.publicKeyDer
      );
      expect(jwkToKeyObjectTransformerSpy).toBeCalledTimes(1);
      // Call again - should use cache
      pubkeyCache.transformJwkToKeyObjectSync(copiedJwk, "RS512", issuer);
      expect(jwkToKeyObjectTransformerSpy).toBeCalledTimes(1);
      // Call again with different alg, should not use cache
      pubkeyCache.transformJwkToKeyObjectSync(copiedJwk, "RS384", issuer);
      expect(jwkToKeyObjectTransformerSpy).toBeCalledTimes(2);
    });
    test("jwk without alg - async", async () => {
      const issuer = "testissuer";
      const jwkToKeyObjectTransformerSpy = jest.fn(
        nodeWebCompat.transformJwkToKeyObjectAsync
      );
      const pubkeyCache = new KeyObjectCache(
        undefined,
        jwkToKeyObjectTransformerSpy
      );
      const copiedJwk = { ...(keypair.jwk as SignatureJwk) };
      delete copiedJwk.alg;
      const pubkey = (await pubkeyCache.transformJwkToKeyObjectAsync(
        copiedJwk,
        "RS512",
        issuer
      )) as KeyObject;
      expect(pubkey.export({ format: "der", type: "spki" })).toEqual(
        keypair.publicKeyDer
      );
      expect(jwkToKeyObjectTransformerSpy).toBeCalledTimes(1);
      // Call again - should use cache
      await pubkeyCache.transformJwkToKeyObjectAsync(
        copiedJwk,
        "RS512",
        issuer
      );
      expect(jwkToKeyObjectTransformerSpy).toBeCalledTimes(1);
      // Call again with different alg, should not use cache
      await pubkeyCache.transformJwkToKeyObjectAsync(
        copiedJwk,
        "RS384",
        issuer
      );
      expect(jwkToKeyObjectTransformerSpy).toBeCalledTimes(2);
    });
    test("no issuer", () => {
      const issuer = undefined;
      const pubkeyCache = new KeyObjectCache();
      const pubkey = pubkeyCache.transformJwkToKeyObjectSync(
        keypair.jwk as SignatureJwk,
        issuer
      ) as KeyObject;
      expect(pubkey.export({ format: "der", type: "spki" })).toEqual(
        keypair.publicKeyDer
      );
    });
    test("no issuer - async", async () => {
      const issuer = undefined;
      const pubkeyCache = new KeyObjectCache();
      const pubkey = (await pubkeyCache.transformJwkToKeyObjectAsync(
        keypair.jwk as SignatureJwk,
        issuer
      )) as KeyObject;
      expect(pubkey.export({ format: "der", type: "spki" })).toEqual(
        keypair.publicKeyDer
      );
    });
    test("no kid", () => {
      const issuer = "testissuer";
      const pubkeyCache = new KeyObjectCache();
      const jwk = { ...keypair.jwk } as SignatureJwk;
      delete jwk.kid;
      const pubkey = pubkeyCache.transformJwkToKeyObjectSync(
        jwk,
        "RS256",
        issuer
      ) as KeyObject;
      expect(pubkey.export({ format: "der", type: "spki" })).toEqual(
        keypair.publicKeyDer
      );
    });
    test("no kid - async", async () => {
      const issuer = "testissuer";
      const pubkeyCache = new KeyObjectCache();
      const jwk = { ...keypair.jwk } as SignatureJwk;
      delete jwk.kid;
      const pubkey = (await pubkeyCache.transformJwkToKeyObjectAsync(
        jwk,
        "RS256",
        issuer
      )) as KeyObject;
      expect(pubkey.export({ format: "der", type: "spki" })).toEqual(
        keypair.publicKeyDer
      );
    });
  });
});

function createSpeedTest(
  options: NonNullable<Parameters<typeof generateKeyPair>[0]>,
  thresholdsInMillis: {
    "verifyJwtSync()": number;
    "verifier.verifySync()": number;
  }
) {
  let keypair: ReturnType<typeof generateKeyPair>;

  beforeAll(() => {
    keypair = generateKeyPair(options);
  });

  const testIdentifier = "crv" in options ? options.crv : options.alg;

  test(`JWT verification is fast –– ${testIdentifier}`, () => {
    const issuer = "testissuer";
    const audience = "testaudience";
    const createSignedJwtInMap = (_: undefined, index: number) =>
      signJwt(
        { kid: keypair.jwk.kid, alg: keypair.jwk.alg },
        {
          hello: `world ${index}`,
          iss: issuer,
          aud: audience,
          now: performance.now(),
        },
        keypair.privateKey
      );
    const testCount = 1000;
    const aWholeLotOfJWTs = [...new Array(testCount)].map(createSignedJwtInMap);
    const start = performance.now();
    for (const jwt of aWholeLotOfJWTs) {
      verifyJwtSync(jwt, keypair.jwk, { issuer, audience });
    }
    const totalTime = performance.now() - start;
    const threshold = thresholdsInMillis["verifyJwtSync()"];
    expect(totalTime).toBeLessThan(testCount * threshold);
    console.log(
      `${testIdentifier} verifyJwtSync(): time per verification: ${(totalTime / testCount).toFixed(3)} ms. (threshold: ${threshold.toFixed(3)})`
    );
  });

  test(`JWT verification with caches is even faster –– ${testIdentifier}`, () => {
    const issuer = "testissuer";
    const audience = "testaudience";
    const createSignedJwtCallbackInMap = (_: undefined, index: number) =>
      signJwt(
        { kid: keypair.jwk.kid, alg: keypair.jwk.alg },
        {
          hello: `world ${index}`,
          iss: issuer,
          aud: audience,
          now: performance.now(),
        },
        keypair.privateKey
      );
    const testCount = 1000;
    const aWholeLotOfJWTs = [...new Array(testCount)].map(
      createSignedJwtCallbackInMap
    );
    const verifier = JwtVerifier.create({
      audience,
      issuer,
      jwksUri: "http://example.com/jwks.json",
    });
    verifier.cacheJwks(keypair.jwks);
    const start = performance.now();
    for (const jwt of aWholeLotOfJWTs) {
      verifier.verifySync(jwt);
    }
    const totalTime = performance.now() - start;
    const threshold = thresholdsInMillis["verifier.verifySync()"];
    expect(totalTime).toBeLessThan(testCount * threshold);
    console.log(
      `${testIdentifier} verifier.verifySync(): time per verification: ${(totalTime / testCount).toFixed(3)} ms. (threshold: ${threshold.toFixed(3)})`
    );
  });
}

describe("speed tests jwt", () => {
  const thresholdsInMillis = {
    "verifyJwtSync()": 0.2, // max 200 microseconds per verifyJwtSync() call
    "verifier.verifySync()": 0.12, // max 120 microseconds per verifier.verifySync() call
  };
  if (process.env.CI) {
    // Increase thresholds on CI to reduce flakiness
    thresholdsInMillis["verifyJwtSync()"] *= 2;
    thresholdsInMillis["verifier.verifySync()"] *= 2;
  }
  const tests: Parameters<typeof createSpeedTest>[] = [
    [{ kty: "RSA", alg: "RS256" }, thresholdsInMillis],
    [{ kty: "RSA", alg: "RS384" }, thresholdsInMillis],
    [{ kty: "RSA", alg: "RS512" }, thresholdsInMillis],
    [{ kty: "EC", alg: "ES256" }, thresholdsInMillis],
    [
      { kty: "EC", alg: "ES384" },
      {
        "verifyJwtSync()": thresholdsInMillis["verifyJwtSync()"] * 4,
        "verifier.verifySync()":
          thresholdsInMillis["verifier.verifySync()"] * 4,
      },
    ],
    [
      { kty: "EC", alg: "ES512" },
      {
        "verifyJwtSync()": thresholdsInMillis["verifyJwtSync()"] * 10,
        "verifier.verifySync()":
          thresholdsInMillis["verifier.verifySync()"] * 10,
      },
    ],
    [{ kty: "OKP", alg: "EdDSA", crv: "Ed25519" }, thresholdsInMillis],
    [
      { kty: "OKP", alg: "EdDSA", crv: "Ed448" },
      {
        "verifyJwtSync()": thresholdsInMillis["verifyJwtSync()"] * 1.5,
        "verifier.verifySync()":
          thresholdsInMillis["verifier.verifySync()"] * 3,
      },
    ],
  ];
  tests.forEach((p) => createSpeedTest(...p));
});
