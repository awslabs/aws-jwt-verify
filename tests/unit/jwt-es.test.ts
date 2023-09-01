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
    keypair = generateKeyPair({ kty: "EC", namedCurve: "P-384" });
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
        console.log(signedJwt);
        expect(
          verifyJwtSync(signedJwt, keypair.jwk, { issuer, audience })
        ).toMatchObject({ hello: "world" });
      });
    });
  });
});
