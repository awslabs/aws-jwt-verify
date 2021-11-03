import {
  generateKeyPair,
  mockHttpsUri,
  signJwt,
  allowAllRealNetworkTraffic,
  disallowAllRealNetworkTraffic,
  publicKeyToJwk,
  base64url,
} from "./test-util";
import { decomposeJwt } from "../../src/jwt";
import {
  JwtInvalidSignatureError,
  JwtInvalidClaimError,
  ParameterValidationError,
  JwtParseError,
  JwtExpiredError,
  JwtNotBeforeError,
  AssertionError,
  KidNotFoundInJwksError,
  JwtWithoutValidKidError,
} from "../../src/error";
import {
  JwtRsaVerifier,
  verifyJwt,
  verifyJwtSync,
  KeyObjectCache,
  transformJwkToKeyObject,
} from "../../src/jwt-rsa";
import { JwksCache, Jwks } from "../../src/jwk";
import { performance } from "perf_hooks";

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
      test("happy flow with jwk", () => {
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
      test("error flow with wrong algorithm", () => {
        const issuer = "https://example.com";
        const audience = "1234";
        const signedJwt = signJwt(
          { kid: keypair.jwk.kid, alg: "RS512" },
          { aud: audience, iss: issuer, hello: "world" },
          keypair.privateKey
        );
        const statement = () =>
          verifyJwtSync(signedJwt, keypair.jwk, { issuer, audience });
        expect(statement).toThrow(AssertionError);
        expect(statement).toThrow(
          "JWT signature algorithm not allowed: RS512. Expected: RS256"
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
        const signedJwt = signJwt({}, {}, keypair.privateKey, false);
        const statement = () =>
          verifyJwtSync(signedJwt, keypair.jwk, {
            audience: null,
            issuer: null,
          });
        expect(statement).toThrow("Invalid signature");
        expect(statement).toThrow(JwtInvalidSignatureError);
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
        expect(statement).toThrow(AssertionError);
      });
      test("missing issuer", () => {
        const signedJwt = signJwt({}, {}, keypair.privateKey);
        const statement = () =>
          verifyJwtSync(signedJwt, keypair.jwk, {
            audience: null,
            issuer: "expectedIssuer",
          });
        expect(statement).toThrow("Missing Issuer. Expected: expectedIssuer");
        expect(statement).toThrow(AssertionError);
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
        const header = base64url("abc");
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
        const header = base64url("123");
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
        const header = base64url('{"alg":"rs256"}');
        const payload = base64url("abc");
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
        const header = base64url('{"alg":"rs256"}');
        const payload = base64url("123");
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
        const header = base64url('{"alg":12345}');
        const payload = base64url('{"iss":"test"}');
        const signedJwt = `${header}.${payload}.signature`;
        const statement = () =>
          verifyJwtSync(signedJwt, keypair.jwk, {
            audience: null,
            issuer: null,
          });
        expect(statement).toThrow("JWT header alg claim is not a string");
        expect(statement).toThrow(JwtParseError);
      });
      test("JWT with iss that is not a string", () => {
        const header = base64url('{"alg":"RS256"}');
        const payload = base64url('{"iss":12345}');
        const signedJwt = `${header}.${payload}.signature`;
        const statement = () =>
          verifyJwtSync(signedJwt, keypair.jwk, {
            audience: null,
            issuer: null,
          });
        expect(statement).toThrow("JWT payload iss claim is not a string");
        expect(statement).toThrow(JwtParseError);
      });
      test("JWT with aud that is not a string", () => {
        const header = base64url('{"alg":"RS256"}');
        const payload = base64url('{"aud":12345}');
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
        const header = base64url('{"alg":"RS256"}');
        const payload = base64url('{"aud":["1234", 5678]}');
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
        const header = base64url('{"alg":"RS256"}');
        const payload = base64url('{"iat":"12345"}');
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
        const signedJwt = signJwt(
          {},
          { exp: exp.valueOf() / 1000 },
          keypair.privateKey
        );
        const statement = () =>
          verifyJwtSync(signedJwt, keypair.jwk, {
            audience: null,
            issuer: null,
          });
        expect(statement).toThrow(`Token expired at ${exp.toISOString()}`);
        expect(statement).toThrow(JwtExpiredError);
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
        expect(statement).toThrow(AssertionError);
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
        expect(statement).toThrow(AssertionError);
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
        expect(statement).toThrow(AssertionError);
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
        const wrongJwk = publicKeyToJwk(keypair.publicKey, { alg: "RS384" });
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
        expect(statement).toThrow(AssertionError);
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
        expect(statement).toThrow(AssertionError);
      });
      test("wrong JWK use", () => {
        const wrongJwk = publicKeyToJwk(keypair.publicKey, { use: "notsig" });
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
        expect(statement).toThrow(AssertionError);
      });
    });
  });

  describe("verify", () => {
    test("happy flow", () => {
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
  });

  describe("JwtVerifier", () => {
    describe("verify", () => {
      test("happy flow", () => {
        const issuer = "https://example.com";
        const verifier = JwtRsaVerifier.create({
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
        const verifier = JwtRsaVerifier.create({
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
      test("jwt without iss claim", () => {
        const signedJwt = signJwt({}, { hello: "world" }, keypair.privateKey);
        const verifier = JwtRsaVerifier.create({
          issuer: "testissuer",
          jwksUri: "https://example.com/keys/jwks.json",
          audience: "1234567890",
        });
        verifier.cacheJwks(keypair.jwks);
        expect.assertions(2);
        const statement = () => verifier.verify(signedJwt);
        expect(statement).rejects.toThrow("iss");
        expect(statement).rejects.toThrow(JwtInvalidClaimError);
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
        const verifier = JwtRsaVerifier.create(
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
        const decomposedJwt = decomposeJwt(signedJwt);
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
        const verifier = JwtRsaVerifier.create({
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
        const verifier = JwtRsaVerifier.create(
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
        const verifier = JwtRsaVerifier.create({
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
        const decomposedJwt = decomposeJwt(signedJwt);
        const customJwtCheck = jest.fn();
        const verifier = JwtRsaVerifier.create({
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
        const verifier = JwtRsaVerifier.create({
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
        const verifier = JwtRsaVerifier.create({
          issuer: "testissuer",
          jwksUri: "https://example.com/keys/jwks.json",
          audience: "1234567890",
        });
        verifier.cacheJwks(keypair.jwks);
        const statement = () => verifier.verifySync(signedJwt);
        expect(statement).toThrow("iss");
        expect(statement).toThrow(JwtInvalidClaimError);
      });
      test("jwt without kid claim", () => {
        const signedJwt = signJwt(
          {},
          { hello: "world", iss: "testissuer" },
          keypair.privateKey
        );
        const verifier = JwtRsaVerifier.create({
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
        const decomposedJwt = decomposeJwt(signedJwt);
        const customJwtCheck = jest.fn().mockImplementation((jwt) => {
          if (jwt.header.typ !== "Expected JWT typ") {
            throw new Error("Oops my custom check failed");
          }
        });
        const verifier = JwtRsaVerifier.create({
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
        const verifier = JwtRsaVerifier.create({
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
        const verifier = JwtRsaVerifier.create({
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
        const verifier = JwtRsaVerifier.create(
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
        const verifier = JwtRsaVerifier.create(identityProviders);
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
        const verifier = JwtRsaVerifier.create(identityProviders);
        const statement = () =>
          verifier.cacheJwks(keypair.jwks, "https://example-3.com");
        expect(statement).toThrow("issuer not configured");
        expect(statement).toThrow(ParameterValidationError);
      });
      test("need at least one issuer config", () => {
        const statement = () => JwtRsaVerifier.create([]);
        expect(statement).toThrow("Provide at least one issuer configuration");
        expect(statement).toThrow(ParameterValidationError);
      });
      test("should provide distinct issuers", () => {
        const issuer = "https://example.com";
        const statement = () =>
          JwtRsaVerifier.create([
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

  describe("public key cache", () => {
    test("happy flow with cache", () => {
      const jwkToKeyObjectTransformerSpy = jest.fn(transformJwkToKeyObject);
      const pubkeyCache = new KeyObjectCache(jwkToKeyObjectTransformerSpy);
      const issuer = "testissuer";
      const pubkey = pubkeyCache.transformJwkToKeyObject(keypair.jwk, issuer);
      expect(pubkey.export({ format: "der", type: "spki" })).toEqual(
        keypair.publicKeyDer
      );
      pubkeyCache.transformJwkToKeyObject(keypair.jwk, "testissuer"); // same JWK, same issuer, transform from cache
      pubkeyCache.transformJwkToKeyObject(keypair.jwk, "othertestissuer");
      // Using a different JWK (with other kid) forces the transformer to run
      expect(jwkToKeyObjectTransformerSpy).toHaveBeenCalledTimes(2);
      const otherKeyPair = generateKeyPair({ kid: "otherkid" });
      pubkeyCache.transformJwkToKeyObject(otherKeyPair.jwk, "testissuer");
      pubkeyCache.transformJwkToKeyObject(otherKeyPair.jwk, "testissuer"); // same JWK, same issuer, transform from cache
      pubkeyCache.transformJwkToKeyObject(otherKeyPair.jwk, "othertestissuer");
      expect(jwkToKeyObjectTransformerSpy).toHaveBeenCalledTimes(4);
      pubkeyCache.clearCache(issuer);
      pubkeyCache.transformJwkToKeyObject(otherKeyPair.jwk, "testissuer"); // Cache is empty, so must be regenerated
      expect(jwkToKeyObjectTransformerSpy).toHaveBeenCalledTimes(5);
    });
    test("no issuer and kid", () => {
      const pubkeyCache = new KeyObjectCache();
      const pubkey = pubkeyCache.transformJwkToKeyObject(keypair.jwk);
      expect(pubkey.export({ format: "der", type: "spki" })).toEqual(
        keypair.publicKeyDer
      );
    });
  });
});

describe("speed tests jwt", () => {
  let keypair: ReturnType<typeof generateKeyPair>;
  beforeAll(() => {
    keypair = generateKeyPair();
  });
  test("JWT verification is fast", () => {
    const issuer = "testissuer";
    const audience = "testaudience";
    const createSignedJwtInMap = (_: undefined, index: number) =>
      signJwt(
        { kid: keypair.jwk.kid },
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
    expect(totalTime).toBeLessThan(testCount * 0.2); // Allowed: max 200 microseconds per verify call
  });

  test("JWT verification with caches is even faster", () => {
    const issuer = "testissuer";
    const audience = "testaudience";
    const createSignedJwtCallbackInMap = (_: undefined, index: number) =>
      signJwt(
        { kid: keypair.jwk.kid },
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
    const verifier = JwtRsaVerifier.create({
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
    expect(totalTime).toBeLessThan(testCount * 0.12); // Allowed: max 120 microseconds per verify call
  });
});
