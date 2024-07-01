import {
  generateKeyPair,
  signJwt,
  allowAllRealNetworkTraffic,
  disallowAllRealNetworkTraffic,
} from "./test-util";
import { verifyJwtSync } from "../../src/jwt-es";
import { JwkValidationError } from "../../src/error";

describe("unit tests jwt verifier ES", () => {
  let keypair: ReturnType<typeof generateKeyPair>;
  beforeAll(() => {
    keypair = generateKeyPair({ kty: "EC", namedCurve: "P-384", alg: "ES384" });
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
          { alg: "ES384", kid: keypair.jwk.kid as string },
          { aud: audience, iss: issuer, hello: "world" },
          keypair.privateKey
        );
        const jwtHeader = JSON.parse(
          Buffer.from(signedJwt.split(".")[0], "base64url").toString()
        );
        expect(jwtHeader).toMatchObject({ alg: "ES384" });
        expect(
          verifyJwtSync(signedJwt, keypair.jwk, { issuer, audience })
        ).toMatchObject({ hello: "world" });
      });

      test("missing crv on JWK", () => {
        const { jwk, privateKey } = generateKeyPair({
          kty: "EC",
          namedCurve: "P-256",
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
      test("missing x on JWK", () => {
        const { jwk, privateKey } = generateKeyPair({
          kty: "EC",
          namedCurve: "P-256",
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
      test("missing y on JWK", () => {
        const { jwk, privateKey } = generateKeyPair({
          kty: "EC",
          namedCurve: "P-256",
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
  });
});
