import {
  generateKeyPair,
  signJwt,
  allowAllRealNetworkTraffic,
  disallowAllRealNetworkTraffic,
  mockHttpsUri,
} from "./test-util";
import { AlbJwtVerifier } from "../../src/alb-verifier";
import { createPublicKey } from "crypto";

describe("unit tests alb verifier", () => {
  let keypair: ReturnType<typeof generateKeyPair>;
  beforeAll(() => {
    keypair = generateKeyPair();
    disallowAllRealNetworkTraffic();
  });
  afterAll(() => {
    allowAllRealNetworkTraffic();
  });

  describe("AlbJwtVerifier", () => {
    describe("verify", () => {
      test("happy flow with cached public key", async () => {
        
        jest.useFakeTimers().setSystemTime(new Date(1727070000 * 1000));
        
        const region = "us-east-1";
        const userPoolId = "us-east-1_123456";
        const loadBalancerArn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-load-balancer/50dc6c495c0c9188";
        const clientId = "my-client-id";
        const issuer = `https://cognito-idp.${region}.amazonaws.com/${userPoolId}`;
        const jwksUri = `https://public-keys.auth.elb.${region}.amazonaws.com`;
        const kid = keypair.jwk.kid;
        const signedJwt = signJwt(
          {
            typ:"JWT",
            kid,
            alg:"RS256",//ES256.
            iss:issuer,
            client:clientId,
            signer:loadBalancerArn,
            exp:1727080000
          },
          {
            hello: "world",
            exp:1727080000,
            iss:issuer,
          },
          keypair.privateKey
        );
        const albVerifier = AlbJwtVerifier.create({
          issuer,
          clientId,
          loadBalancerArn,
          jwksUri
        });
        albVerifier.cacheJwks(keypair.jwks);
        expect.assertions(1);
        expect(
          await albVerifier.verify(signedJwt)
        ).toMatchObject({ hello: "world" });
      });

      test("happy flow with public key fetching", async () => {
        
        jest.useFakeTimers().setSystemTime(new Date(1727070000 * 1000));
        
        const region = "us-east-1";
        const userPoolId = "us-east-1_123456";
        const loadBalancerArn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-load-balancer/50dc6c495c0c9188";
        const clientId = "my-client-id";
        const issuer = `https://cognito-idp.${region}.amazonaws.com/${userPoolId}`;
        const jwksUri = `https://public-keys.auth.elb.${region}.amazonaws.com`;
        const jwk = keypair.jwk;
        const kid = jwk.kid;
        
        const pem = createPublicKey({
            key: jwk,
            format: "jwk",
          }).export({
            format: "pem",
            type: "spki",
          });

        mockHttpsUri(`${jwksUri}/${kid}`, {
          responsePayload: pem,
        });

        const signedJwt = signJwt(
          {
            typ:"JWT",
            kid,
            alg:"RS256",//ES256.
            iss:issuer,
            client:clientId,
            signer:loadBalancerArn,
            exp:1727080000
          },
          {
            hello: "world",
            exp:1727080000,
            iss:issuer,
          },
          keypair.privateKey
        );
        const albVerifier = AlbJwtVerifier.create({
          issuer,
          clientId,
          loadBalancerArn,
          jwksUri
        });
        expect.assertions(1);
        expect(
          await albVerifier.verify(signedJwt)
        ).toMatchObject({ hello: "world" });
      });
    });
  });
});
