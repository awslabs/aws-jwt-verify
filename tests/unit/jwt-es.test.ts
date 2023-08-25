import {
  generateKeyPair,
  signJwt,
  allowAllRealNetworkTraffic,
  disallowAllRealNetworkTraffic,
} from "./test-util";
import { verifyJwtSync } from "../../src/jwt-es";

describe("unit tests jwt verifier ES", () => {
  let keypair: ReturnType<typeof generateKeyPair>;
  beforeAll(() => {
    keypair = generateKeyPair({ alg: "ES384" });
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
          { alg: "ES384", kid: keypair.jwk.kid },
          { aud: audience, iss: issuer, hello: "world" },
          keypair.privateKey
        );
        expect(
          verifyJwtSync(signedJwt, keypair.jwk, { issuer, audience })
        ).toMatchObject({ hello: "world" });
      });
    });
  });
});
