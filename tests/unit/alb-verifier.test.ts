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
        
        const region = "us-east-1";
        const userPoolId = "us-east-1_123456";
        const loadBalancerArn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-load-balancer/50dc6c495c0c9188";
        const clientId = "my-client-id";
        const issuer = `https://cognito-idp.${region}.amazonaws.com/${userPoolId}`;
        const jwksUri = `https://public-keys.auth.elb.${region}.amazonaws.com`;
        const kid = keypair.jwk.kid;
        const exp = 4000000000;// nock and jest.useFakeTimers do not work well together. Used of a long expired date instead
        
        const signedJwt = signJwt(
          {
            typ:"JWT",
            kid,
            alg:"RS256",//ES256.
            iss:issuer,
            client:clientId,
            signer:loadBalancerArn,
            exp
          },
          {
            hello: "world",
            exp,
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
        
        const region = "us-east-1";
        const userPoolId = "us-east-1_123456";
        const loadBalancerArn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-load-balancer/50dc6c495c0c9188";
        const clientId = "my-client-id";
        const issuer = `https://cognito-idp.${region}.amazonaws.com/${userPoolId}`;
        const jwksUri = `https://public-keys.auth.elb.${region}.amazonaws.com`;
        const jwk = keypair.jwk;
        const kid = jwk.kid;
        const exp = 4000000000;// nock and jest.useFakeTimers do not work well together. Used of a long expired date instead
        const pem = createPublicKey({
            key: jwk,
            format: "jwk",
          }).export({
            format: "pem",
            type: "spki",
          });//pem with -----BEGIN PUBLIC KEY----- and -----END PUBLIC KEY-----.


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
            exp
          },
          {
            hello: "world",
            exp,
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
