import {
  generateKeyPair,
  signJwt,
  allowAllRealNetworkTraffic,
  disallowAllRealNetworkTraffic,
  mockHttpsUri,
} from "./test-util";
import { AlbJwtInvalidClientIdError, AlbJwtInvalidSignerError, AlbDataVerifier } from "../../src/alb-verifier";
import { createPublicKey } from "crypto";
import { JwtInvalidIssuerError } from "../../src/error";

describe("unit tests alb verifier", () => {
  let keypair: ReturnType<typeof generateKeyPair>;
  beforeAll(() => {
    keypair = generateKeyPair({
      kid:"00000000-0000-0000-0000-000000000000",
      kty:"EC",
      alg:"ES256",
    });
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
            alg:"ES256",
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
        const albVerifier = AlbDataVerifier.create({
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
            alg:"ES256",
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
        const albVerifier = AlbDataVerifier.create({
          issuer,
          clientId,
          loadBalancerArn,
          jwksUri,
        });
        expect.assertions(1);
        expect(
          await albVerifier.verify(signedJwt)
        ).toMatchObject({ hello: "world" });
      });

      
      test("happy flow with lazy property", async () => {
        
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
            alg:"ES256",
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
        const albVerifier = AlbDataVerifier.create({
          loadBalancerArn
        });
        expect.assertions(1);
        expect(
          await albVerifier.verify(signedJwt,{
            issuer,
            clientId,
            jwksUri,
          })
        ).toMatchObject({ hello: "world" });
      });

      
      test("flow with no jwksUri", async () => {
        
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
            alg:"ES256",
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
        const albVerifier = AlbDataVerifier.create({
          issuer,
          clientId,
          loadBalancerArn,
        });
        expect.assertions(1);
        expect(
          await albVerifier.verify(signedJwt)
        ).toMatchObject({ hello: "world" });
      });

      test("happy flow with multi properties", async () => {

        const keypair1 = generateKeyPair({kty:"EC",alg:"ES256",kid:"11111111-1111-1111-1111-111111111111"});
        const keypair2 = generateKeyPair({kty:"EC",alg:"ES256",kid:"22222222-2222-2222-2222-222222222222"});
        
        const region = "us-east-1";
        const userPoolId = "us-east-1_123456";
        const loadBalancerArn1 = "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-load-balancer/AAAAAAAAAAAAAAAA";
        const loadBalancerArn2 = "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-load-balancer/BBBBBBBBBBBBBBBB";
        const clientId = "my-client-id";
        const issuer = `https://cognito-idp.${region}.amazonaws.com/${userPoolId}`;
        const jwksUri = `https://public-keys.auth.elb.${region}.amazonaws.com`;
        const exp = 4000000000;// nock and jest.useFakeTimers do not work well together. Used of a long expired date instead

        mockHttpsUri(`${jwksUri}/${keypair1.jwk.kid}`, {
          responsePayload: createPublicKey({
            key: keypair1.jwk,
            format: "jwk",
          }).export({
            format: "pem",
            type: "spki",
          }),
        });

        mockHttpsUri(`${jwksUri}/${keypair2.jwk.kid}`, {
          responsePayload: createPublicKey({
            key: keypair2.jwk,
            format: "jwk",
          }).export({
            format: "pem",
            type: "spki",
          }),
        });
        
        const signedJwt1 = signJwt(
          {
            typ:"JWT",
            kid:keypair1.jwk.kid,
            alg:"ES256",
            iss:issuer,
            client:clientId,
            signer:loadBalancerArn1,
            exp
          },
          {
            hello: "world1",
            exp,
            iss:issuer,
          },
          keypair1.privateKey
        );

        const signedJwt2 = signJwt(
          {
            typ:"JWT",
            kid:keypair2.jwk.kid,
            alg:"ES256",
            iss:issuer,
            client:clientId,
            signer:loadBalancerArn2,
            exp
          },
          {
            hello: "world2",
            exp,
            iss:issuer,
          },
          keypair2.privateKey
        );
        const albVerifier = AlbDataVerifier.create([{
          issuer,
          clientId,
          loadBalancerArn:loadBalancerArn1,
          jwksUri,
        },{
          issuer,
          clientId,
          loadBalancerArn:loadBalancerArn2,
          jwksUri,
        }]);
        
        expect.assertions(2);

        expect(
          await albVerifier.verify(signedJwt1)
        ).toMatchObject({ hello: "world1" });

        expect(
          await albVerifier.verify(signedJwt2)
        ).toMatchObject({ hello: "world2" });
      });

      test("happy flow with default jwksUri", async () => {

        const region = "us-east-1";
        const userPoolId = "us-east-1_123456";
        const loadBalancerArn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-load-balancer/AAAAAAAAAAAAAAAA";
        const clientId = "my-client-id";
        const issuer = `https://cognito-idp.${region}.amazonaws.com/${userPoolId}`;
        const exp = 4000000000;// nock and jest.useFakeTimers do not work well together. Used of a long expired date instead

        const signedJwt = signJwt(
          {
            typ:"JWT",
            kid:keypair.jwk.kid,
            alg:"ES256",
            iss:issuer,
            client:clientId,
            signer:loadBalancerArn,
            exp
          },
          {
            hello: "world1",
            exp,
            iss:issuer,
          },
          keypair.privateKey
        );

        const albVerifier = AlbDataVerifier.create({
          issuer,
          clientId,
          loadBalancerArn:loadBalancerArn,
        });

        albVerifier.cacheJwks(keypair.jwks,loadBalancerArn);

        expect.assertions(1);

        expect(
          await albVerifier.verify(signedJwt)
        ).toMatchObject({ hello: "world1" });

      });

      test("invalid issuer", () => {
        
        const region = "us-east-1";
        const userPoolId = "us-east-1_123456";
        const loadBalancerArn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-load-balancer/50dc6c495c0c9188";
        const clientId = "my-client-id";
        const badIssuer = `https://badissuer.amazonaws.com`;
        const issuer = `https://cognito-idp.${region}.amazonaws.com/${userPoolId}`;
        const jwksUri = `https://public-keys.auth.elb.${region}.amazonaws.com`;
        const kid = keypair.jwk.kid;
        const exp = 4000000000;// nock and jest.useFakeTimers do not work well together. Used of a long expired date instead
        
        const signedJwt = signJwt(
          {
            typ:"JWT",
            kid,
            alg:"ES256",
            iss:badIssuer,
            client:clientId,
            signer:loadBalancerArn,
            exp
          },
          {
            hello: "world",
            exp,
            iss:badIssuer,
          },
          keypair.privateKey
        );
        const albVerifier = AlbDataVerifier.create({
          issuer,
          clientId,
          loadBalancerArn,
          jwksUri
        });
        
        albVerifier.cacheJwks(keypair.jwks);

        expect.assertions(1);
        expect(
          albVerifier.verify(signedJwt)
        ).rejects.toThrow(JwtInvalidIssuerError);
      });

      test("invalid signer", () => {
        
        const region = "us-east-1";
        const userPoolId = "us-east-1_123456";
        const loadBalancerArn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-load-balancer/50dc6c495c0c9188";
        const badSigner = "arn:aws:elasticloadbalancing:us-east-1:badaccount:loadbalancer/app/badloadbalancer/50dc6c495c0c9188";
        const clientId = "my-client-id";
        const issuer = `https://cognito-idp.${region}.amazonaws.com/${userPoolId}`;
        const jwksUri = `https://public-keys.auth.elb.${region}.amazonaws.com`;
        const kid = keypair.jwk.kid;
        const exp = 4000000000;// nock and jest.useFakeTimers do not work well together. Used of a long expired date instead
        
        const signedJwt = signJwt(
          {
            typ:"JWT",
            kid,
            alg:"ES256",
            iss:issuer,
            client:clientId,
            signer:badSigner,
            exp
          },
          {
            hello: "world",
            exp,
            iss:issuer,
          },
          keypair.privateKey
        );
        const albVerifier = AlbDataVerifier.create({
          issuer,
          clientId,
          loadBalancerArn,
          jwksUri
        });
        
        albVerifier.cacheJwks(keypair.jwks);

        expect.assertions(1);
        expect(
          albVerifier.verify(signedJwt)
        ).rejects.toThrow(AlbJwtInvalidSignerError);
      });

      
      test("invalid client id", () => {
        
        const region = "us-east-1";
        const userPoolId = "us-east-1_123456";
        const loadBalancerArn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-load-balancer/50dc6c495c0c9188";
        const clientId = "my-client-id";
        const badClientId = "bad-client-id";
        const issuer = `https://cognito-idp.${region}.amazonaws.com/${userPoolId}`;
        const jwksUri = `https://public-keys.auth.elb.${region}.amazonaws.com`;
        const kid = keypair.jwk.kid;
        const exp = 4000000000;// nock and jest.useFakeTimers do not work well together. Used of a long expired date instead
        
        const signedJwt = signJwt(
          {
            typ:"JWT",
            kid,
            alg:"ES256",
            iss:issuer,
            client:badClientId,
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
        const albVerifier = AlbDataVerifier.create({
          issuer,
          clientId,
          loadBalancerArn,
          jwksUri
        });
        
        albVerifier.cacheJwks(keypair.jwks);

        expect.assertions(1);
        expect(
          albVerifier.verify(signedJwt)
        ).rejects.toThrow(AlbJwtInvalidClientIdError);
      });

      test("null client id", async () => {
        
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
            alg:"ES256",
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
        const albVerifier = AlbDataVerifier.create({
          issuer,
          clientId:null,
          loadBalancerArn,
          jwksUri
        });
        
        albVerifier.cacheJwks(keypair.jwks);

        expect.assertions(1);
        expect(
          await albVerifier.verify(signedJwt)
        ).toMatchObject({ hello: "world" });
      });

    });
  });
});
