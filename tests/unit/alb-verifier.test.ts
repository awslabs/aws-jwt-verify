import {
  generateKeyPair,
  signJwt,
  allowAllRealNetworkTraffic,
  disallowAllRealNetworkTraffic,
  mockHttpsUri,
} from "./test-util";
import { decomposeUnverifiedJwt } from "../../src/jwt";
import {
  AlbJwtVerifier,
  AlbJwtVerifierMultiProperties,
} from "../../src/alb-verifier";
import {
  ParameterValidationError,
  JwtInvalidClaimError,
  JwtInvalidIssuerError,
  AlbJwtInvalidSignerError,
  AlbJwtInvalidClientIdError,
} from "../../src/error";
import { createPublicKey } from "crypto";
import { KeyPair } from "../util/util";

describe("unit tests alb verifier", () => {
  let keypair: ReturnType<typeof generateKeyPair>;
  beforeAll(() => {
    keypair = generateKeyPair({
      kid: "00000000-0000-0000-0000-000000000000",
      kty: "EC",
      alg: "ES256",
    });
    disallowAllRealNetworkTraffic();
  });
  afterAll(() => {
    allowAllRealNetworkTraffic();
  });

  describe("AlbJwtVerifier", () => {
    describe("verify", () => {
      test("happy flow", async () => {
        const kid = keypair.jwk.kid;
        const issuer = `https://cognito-idp.us-east-1.amazonaws.com/us-east-1_123456`;
        const albArn =
          "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-load-balancer/50dc6c495c0c9188";
        const clientId = "my-client-id";
        const exp = 4000000000; // Use of a long expiry date

        const signedJwt = signJwt(
          {
            typ: "JWT",
            kid,
            alg: "ES256",
            iss: issuer,
            client: clientId,
            signer: albArn,
            exp,
          },
          {
            hello: "world",
            exp,
            iss: issuer,
          },
          keypair.privateKey
        );
        const decomposedJwt = decomposeUnverifiedJwt(signedJwt);
        const customJwtCheck = jest.fn();
        const albVerifier = AlbJwtVerifier.create({
          albArn,
          issuer,
          customJwtCheck,
        });
        albVerifier.cacheJwks(keypair.jwks);
        expect.assertions(2);
        expect(
          await albVerifier.verify(signedJwt, {
            clientId: null,
          })
        ).toMatchObject({ hello: "world" });
        expect(customJwtCheck).toHaveBeenCalledWith({
          header: decomposedJwt.header,
          payload: decomposedJwt.payload,
          jwk: keypair.jwk,
        });
      });
    });
    describe("validateAlbJwtParams", () => {
      test("invalid load balancer ARN - too short", async () => {
        const issuer = `https://cognito-idp.us-east-1.amazonaws.com/us-east-1_123456`;
        const albArn = "arn:aws:elasticloadbalancing";

        expect(() =>
          AlbJwtVerifier.create({
            albArn,
            issuer,
          })
        ).toThrow(
          new ParameterValidationError(
            `Invalid load balancer ARN: arn:aws:elasticloadbalancing`
          )
        );
      });

      test("invalid load balancer ARN - invalid region", async () => {
        const issuer = `https://cognito-idp.us-east-1.amazonaws.com/us-east-1_123456`;
        const albArn =
          "arn:aws:elasticloadbalancing:.:123456789012:loadbalancer/app/my-load-balancer/50dc6c495c0c9188";

        expect(() =>
          AlbJwtVerifier.create({
            albArn,
            issuer,
          })
        ).toThrow(
          new ParameterValidationError(
            `Invalid load balancer ARN: arn:aws:elasticloadbalancing:.:123456789012:loadbalancer/app/my-load-balancer/50dc6c495c0c9188`
          )
        );
      });
    });
    describe("includeRawJwtInErrors", () => {
      test("verify - flag set at statement level", () => {
        const kid = keypair.jwk.kid;
        const issuer = `https://cognito-idp.us-east-1.amazonaws.com/us-east-1_123456`;
        const albArn =
          "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-load-balancer/50dc6c495c0c9188";
        const clientId = "my-client-id";
        const exp = 4000000000; // Use of a long expiry date

        const header = {
          typ: "JWT",
          kid,
          alg: "ES256",
          iss: "badissuer",
          client: clientId,
          signer: albArn,
          exp,
        };
        const payload = {
          hello: "world",
          exp,
          iss: "badissuer",
        };
        const signedJwt = signJwt(header, payload, keypair.privateKey);
        const albVerifier = AlbJwtVerifier.create({
          albArn,
          issuer,
        });
        albVerifier.cacheJwks(keypair.jwks);
        const statement = () =>
          albVerifier.verify(signedJwt, {
            clientId: null,
            includeRawJwtInErrors: true,
          });
        expect.assertions(2);
        expect(statement).rejects.toThrow(JwtInvalidIssuerError);
        return statement().catch((err) => {
          expect((err as JwtInvalidClaimError).rawJwt).toMatchObject({
            header,
            payload,
          });
        });
      });
      test("verify - flag set at verifier level", () => {
        const kid = keypair.jwk.kid;
        const issuer = `https://cognito-idp.us-east-1.amazonaws.com/us-east-1_123456`;
        const albArn =
          "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-load-balancer/50dc6c495c0c9188";
        const clientId = "my-client-id";
        const exp = 4000000000; // Use of a long expiry date
        const header = {
          typ: "JWT",
          kid,
          alg: "ES256",
          iss: "badissuer",
          client: clientId,
          signer: albArn,
          exp,
        };
        const payload = {
          hello: "world",
          exp,
          iss: "badissuer",
        };
        const signedJwt = signJwt(header, payload, keypair.privateKey);
        const albVerifier = AlbJwtVerifier.create({
          albArn,
          issuer,
          includeRawJwtInErrors: true,
        });
        albVerifier.cacheJwks(keypair.jwks);
        const statement = () =>
          albVerifier.verify(signedJwt, {
            clientId: null,
          });
        expect.assertions(2);
        expect(statement).rejects.toThrow();
        return statement().catch((err) => {
          expect((err as JwtInvalidClaimError).rawJwt).toMatchObject({
            header,
            payload,
          });
        });
      });
      test("verify - flag NOT set", () => {
        const kid = keypair.jwk.kid;
        const issuer = `https://cognito-idp.us-east-1.amazonaws.com/us-east-1_123456`;
        const albArn =
          "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-load-balancer/50dc6c495c0c9188";
        const clientId = "my-client-id";
        const exp = 4000000000; // Use of a long expiry date
        const header = {
          typ: "JWT",
          kid,
          alg: "ES256",
          iss: "badissuer",
          client: clientId,
          signer: albArn,
          exp,
        };
        const payload = {
          hello: "world",
          exp,
          iss: "badissuer",
        };
        const signedJwt = signJwt(header, payload, keypair.privateKey);
        const albVerifier = AlbJwtVerifier.create({
          albArn,
          issuer,
        });
        albVerifier.cacheJwks(keypair.jwks);
        const statement = () =>
          albVerifier.verify(signedJwt, {
            clientId: null,
          });
        expect.assertions(2);
        expect(statement).rejects.toThrow(JwtInvalidIssuerError);
        return statement().catch((err) => {
          expect((err as JwtInvalidClaimError).rawJwt).toBe(undefined);
        });
      });
      test("verifySync - flag set at verifier level", () => {
        const kid = keypair.jwk.kid;
        const issuer = `https://cognito-idp.us-east-1.amazonaws.com/us-east-1_123456`;
        const albArn =
          "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-load-balancer/50dc6c495c0c9188";
        const clientId = "my-client-id";
        const exp = 4000000000; // Use of a long expiry date
        const header = {
          typ: "JWT",
          kid,
          alg: "ES256",
          iss: "badissuer",
          client: clientId,
          signer: albArn,
          exp,
        };
        const payload = {
          hello: "world",
          exp,
          iss: "badissuer",
        };
        const signedJwt = signJwt(header, payload, keypair.privateKey);
        const albVerifier = AlbJwtVerifier.create({
          albArn,
          issuer,
          includeRawJwtInErrors: true,
        });
        albVerifier.cacheJwks(keypair.jwks);
        const statement = () =>
          albVerifier.verifySync(signedJwt, {
            clientId: null,
          });
        expect.assertions(2);
        expect(statement).toThrow(JwtInvalidIssuerError);
        try {
          statement();
        } catch (err) {
          expect((err as JwtInvalidClaimError).rawJwt).toMatchObject({
            header,
            payload,
          });
        }
      });
      test("verifySync - flag NOT set", () => {
        const kid = keypair.jwk.kid;
        const issuer = `https://cognito-idp.us-east-1.amazonaws.com/us-east-1_123456`;
        const albArn =
          "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-load-balancer/50dc6c495c0c9188";
        const clientId = "my-client-id";
        const exp = 4000000000; // Use of a long expiry date
        const header = {
          typ: "JWT",
          kid,
          alg: "ES256",
          iss: "badissuer",
          client: clientId,
          signer: albArn,
          exp,
        };
        const payload = {
          hello: "world",
          exp,
          iss: "badissuer",
        };
        const signedJwt = signJwt(header, payload, keypair.privateKey);
        const albVerifier = AlbJwtVerifier.create({
          albArn,
          issuer,
        });
        albVerifier.cacheJwks(keypair.jwks);
        const statement = () =>
          albVerifier.verifySync(signedJwt, {
            clientId: null,
          });
        expect.assertions(2);
        expect(statement).toThrow(JwtInvalidIssuerError);
        try {
          statement();
        } catch (err) {
          expect((err as JwtInvalidClaimError).rawJwt).toEqual(undefined);
        }
      });
    });
    describe("verifySync", () => {
      test("happy flow", () => {
        const kid = keypair.jwk.kid;
        const issuer = `https://cognito-idp.us-east-1.amazonaws.com/us-east-1_123456`;
        const albArn =
          "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-load-balancer/50dc6c495c0c9188";
        const clientId = "my-client-id";
        const exp = 4000000000; // Use of a long expiry date

        const signedJwt = signJwt(
          {
            typ: "JWT",
            kid,
            alg: "ES256",
            iss: issuer,
            client: clientId,
            signer: albArn,
            exp,
          },
          {
            hello: "world",
            exp,
            iss: issuer,
          },
          keypair.privateKey
        );
        const albVerifier = AlbJwtVerifier.create({
          albArn,
          issuer,
        });
        albVerifier.cacheJwks(keypair.jwks);
        expect(
          albVerifier.verifySync(signedJwt, {
            clientId: null,
          })
        ).toMatchObject({ hello: "world" });
      });

      test("clientId null", async () => {
        const albArn =
          "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-load-balancer/50dc6c495c0c9188";
        const clientId = "my-client-id";
        const issuer = `https://cognito-idp.us-east-1.amazonaws.com/us-east-1_123456`;
        const jwksUri = `https://public-keys.auth.elb.us-east-1.amazonaws.com`;
        const kid = keypair.jwk.kid;
        const exp = 4000000000; // Use of a long expiry date

        const signedJwt = signJwt(
          {
            typ: "JWT",
            kid,
            alg: "ES256",
            iss: issuer,
            client: clientId,
            signer: albArn,
            exp,
          },
          {
            hello: "world",
            exp,
            iss: issuer,
          },
          keypair.privateKey
        );
        const albVerifier = AlbJwtVerifier.create({
          issuer,
          clientId: null,
          albArn,
          jwksUri,
        });

        albVerifier.cacheJwks(keypair.jwks);

        expect.assertions(1);
        expect(albVerifier.verifySync(signedJwt)).toMatchObject({
          hello: "world",
        });
      });

      test("clientId undefined", () => {
        const kid = keypair.jwk.kid;
        const issuer = `https://cognito-idp.us-east-1.amazonaws.com/us-east-1_123456`;
        const albArn =
          "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-load-balancer/50dc6c495c0c9188";
        const clientId = "my-client-id";
        const exp = 4000000000; // Use of a long expiry date

        const signedJwt = signJwt(
          {
            typ: "JWT",
            kid,
            alg: "ES256",
            iss: issuer,
            client: clientId,
            signer: albArn,
            exp,
          },
          {
            hello: "world",
            exp,
            iss: issuer,
          },
          keypair.privateKey
        );
        const verifier = AlbJwtVerifier.create({
          albArn,
          issuer,
          clientId: undefined as unknown as null,
        });
        verifier.cacheJwks(keypair.jwks);

        expect.assertions(2);
        expect(() => verifier.verifySync(signedJwt)).toThrow(
          "clientId must be provided or set to null explicitly"
        );
        expect(() => verifier.verifySync(signedJwt)).toThrow(
          ParameterValidationError
        );
      });

      test("invalid issuer", () => {
        const albArn =
          "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-load-balancer/50dc6c495c0c9188";
        const clientId = "my-client-id";
        const badIssuer = `https://badissuer.amazonaws.com`;
        const issuer = `https://cognito-idp.us-east-1.amazonaws.com/us-east-1_123456`;
        const jwksUri = `https://public-keys.auth.elb.us-east-1.amazonaws.com`;
        const kid = keypair.jwk.kid;
        const exp = 4000000000; // Use of a long expiry date

        const signedJwt = signJwt(
          {
            typ: "JWT",
            kid,
            alg: "ES256",
            iss: badIssuer,
            client: clientId,
            signer: albArn,
            exp,
          },
          {
            hello: "world",
            exp,
            iss: badIssuer,
          },
          keypair.privateKey
        );
        const albVerifier = AlbJwtVerifier.create({
          issuer,
          clientId,
          albArn,
          jwksUri,
        });

        albVerifier.cacheJwks(keypair.jwks);

        expect.assertions(1);
        expect(() => albVerifier.verifySync(signedJwt)).toThrow(
          JwtInvalidIssuerError
        );
      });

      test("invalid signer", () => {
        const albArn =
          "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-load-balancer/50dc6c495c0c9188";
        const badSigner =
          "arn:aws:elasticloadbalancing:us-east-1:badaccount:loadbalancer/app/badloadbalancer/50dc6c495c0c9188";
        const clientId = "my-client-id";
        const issuer = `https://cognito-idp.us-east-1.amazonaws.com/us-east-1_123456`;
        const jwksUri = `https://public-keys.auth.elb.us-east-1.amazonaws.com`;
        const kid = keypair.jwk.kid;
        const exp = 4000000000; // Use of a long expiry date

        const signedJwt = signJwt(
          {
            typ: "JWT",
            kid,
            alg: "ES256",
            iss: issuer,
            client: clientId,
            signer: badSigner,
            exp,
          },
          {
            hello: "world",
            exp,
            iss: issuer,
          },
          keypair.privateKey
        );
        const albVerifier = AlbJwtVerifier.create({
          issuer,
          clientId,
          albArn,
          jwksUri,
        });

        albVerifier.cacheJwks(keypair.jwks);

        expect.assertions(1);
        expect(() => albVerifier.verifySync(signedJwt)).toThrow(
          AlbJwtInvalidSignerError
        );
      });

      test("invalid clientId", () => {
        const albArn =
          "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-load-balancer/50dc6c495c0c9188";
        const clientId = "my-client-id";
        const badClientId = "bad-client-id";
        const issuer = `https://cognito-idp.us-east-1.amazonaws.com/us-east-1_123456`;
        const jwksUri = `https://public-keys.auth.elb.us-east-1.amazonaws.com`;
        const kid = keypair.jwk.kid;
        const exp = 4000000000; // Use of a long expiry date

        const signedJwt = signJwt(
          {
            typ: "JWT",
            kid,
            alg: "ES256",
            iss: issuer,
            client: badClientId,
            signer: albArn,
            exp,
          },
          {
            hello: "world",
            exp,
            iss: issuer,
          },
          keypair.privateKey
        );
        const albVerifier = AlbJwtVerifier.create({
          issuer,
          clientId,
          albArn,
          jwksUri,
        });

        albVerifier.cacheJwks(keypair.jwks);

        expect.assertions(1);
        expect(() => albVerifier.verifySync(signedJwt)).toThrow(
          AlbJwtInvalidClientIdError
        );
      });
    });
    describe("jwksUri", () => {
      test("default jwksUri in us-east-1", async () => {
        const albArn =
          "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-load-balancer/50dc6c495c0c9188";
        const clientId = "my-client-id";
        const issuer = `https://cognito-idp.us-east-1.amazonaws.com/us-east-1_123456`;
        const jwksUri = `https://public-keys.auth.elb.us-east-1.amazonaws.com`;
        const jwk = keypair.jwk;
        const kid = jwk.kid;
        const exp = 4000000000; // Use of a long expiry date
        const pem = createPublicKey({
          key: jwk,
          format: "jwk",
        }).export({
          format: "pem",
          type: "spki",
        }); //pem with -----BEGIN PUBLIC KEY----- and -----END PUBLIC KEY-----.

        mockHttpsUri(`${jwksUri}/${kid}`, {
          responsePayload: pem,
        });

        const signedJwt = signJwt(
          {
            typ: "JWT",
            kid,
            alg: "ES256",
            iss: issuer,
            client: clientId,
            signer: albArn,
            exp,
          },
          {
            hello: "world",
            exp,
            iss: issuer,
          },
          keypair.privateKey
        );
        const albVerifier = AlbJwtVerifier.create({
          issuer,
          clientId,
          albArn,
        });
        expect.assertions(1);
        expect(await albVerifier.verify(signedJwt)).toMatchObject({
          hello: "world",
        });
      });

      test("default jwksUri in eu-west-2", async () => {
        const albArn =
          "arn:aws:elasticloadbalancing:eu-west-2:123456789012:loadbalancer/app/my-load-balancer/50dc6c495c0c9188";
        const clientId = "my-client-id";
        const issuer = `https://cognito-idp.eu-west-2.amazonaws.com/eu-west-2_123456`;
        const jwksUri = `https://public-keys.auth.elb.eu-west-2.amazonaws.com`;
        const jwk = keypair.jwk;
        const kid = jwk.kid;
        const exp = 4000000000; // Use of a long expiry date
        const pem = createPublicKey({
          key: jwk,
          format: "jwk",
        }).export({
          format: "pem",
          type: "spki",
        }); //pem with -----BEGIN PUBLIC KEY----- and -----END PUBLIC KEY-----.

        mockHttpsUri(`${jwksUri}/${kid}`, {
          responsePayload: pem,
        });

        const signedJwt = signJwt(
          {
            typ: "JWT",
            kid,
            alg: "ES256",
            iss: issuer,
            client: clientId,
            signer: albArn,
            exp,
          },
          {
            hello: "world",
            exp,
            iss: issuer,
          },
          keypair.privateKey
        );
        const albVerifier = AlbJwtVerifier.create({
          issuer,
          clientId,
          albArn,
        });
        expect.assertions(1);
        expect(await albVerifier.verify(signedJwt)).toMatchObject({
          hello: "world",
        });
      });

      test("custom jwksUri", async () => {
        const albArn =
          "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-load-balancer/50dc6c495c0c9188";
        const clientId = "my-client-id";
        const issuer = `https://cognito-idp.us-east-1.amazonaws.com/us-east-1_123456`;
        const jwksUri = `https://s3-us-gov-west-1.amazonaws.com/aws-elb-public-keys-prod-us-gov-west-1`;
        const jwk = keypair.jwk;
        const kid = jwk.kid;
        const exp = 4000000000; // Use of a long expiry date
        const pem = createPublicKey({
          key: jwk,
          format: "jwk",
        }).export({
          format: "pem",
          type: "spki",
        }); //pem with -----BEGIN PUBLIC KEY----- and -----END PUBLIC KEY-----.

        mockHttpsUri(`${jwksUri}/${kid}`, {
          responsePayload: pem,
        });

        const signedJwt = signJwt(
          {
            typ: "JWT",
            kid,
            alg: "ES256",
            iss: issuer,
            client: clientId,
            signer: albArn,
            exp,
          },
          {
            hello: "world",
            exp,
            iss: issuer,
          },
          keypair.privateKey
        );
        const albVerifier = AlbJwtVerifier.create({
          issuer,
          clientId,
          albArn,
          jwksUri,
        });
        expect.assertions(1);
        expect(await albVerifier.verify(signedJwt)).toMatchObject({
          hello: "world",
        });
      });
    });
  });

  describe("AlbJwtVerifier with multiple alb", () => {
    describe("verifySync", () => {
      test("happy flow with 2 albs and 2 issuers", async () => {
        const exp = 4000000000; // Use of a long expiry date

        const identityProviders: {
          config: AlbJwtVerifierMultiProperties;
          keypair: KeyPair;
        }[] = [
          {
            config: {
              albArn:
                "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-load-balancer/60dc6c495c0c9188",
              issuer:
                "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_qbc",

              clientId: "client1",
            },
            keypair: generateKeyPair({
              kid: "11111111-1111-1111-1111-111111111111",
              kty: "EC",
              alg: "ES256",
            }),
          },
          {
            config: {
              albArn:
                "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-load-balancer/",
              issuer:
                "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_def",
              clientId: "client2",
            },
            keypair: generateKeyPair({
              kid: "22222222-2222-2222-2222-222222222222",
              kty: "EC",
              alg: "ES256",
            }),
          },
        ];
        const verifier = AlbJwtVerifier.create(
          identityProviders.map((idp) => idp.config)
        );

        expect.assertions(identityProviders.length);
        for (const idp of identityProviders) {
          verifier.cacheJwks(idp.keypair.jwks, idp.config.issuer);
          const signedJwt = signJwt(
            {
              typ: "JWT",
              kid: idp.keypair.jwk.kid,
              alg: "ES256",
              iss: idp.config.issuer,
              client: idp.config.clientId,
              signer: idp.config.albArn,
              exp,
            },
            {
              hello: "world",
              exp,
              iss: idp.config.issuer,
            },
            idp.keypair.privateKey
          );
          expect(verifier.verify(signedJwt)).resolves.toMatchObject({
            hello: "world",
          });
        }
      });

      test("happy flow with 2 albs and 1 issuer", async () => {
        const keypair1 = generateKeyPair({
          kty: "EC",
          alg: "ES256",
          kid: "11111111-1111-1111-1111-111111111111",
        });
        const keypair2 = generateKeyPair({
          kty: "EC",
          alg: "ES256",
          kid: "22222222-2222-2222-2222-222222222222",
        });

        const albArn1 =
          "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-load-balancer/AAAAAAAAAAAAAAAA";
        const albArn2 =
          "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-load-balancer/BBBBBBBBBBBBBBBB";
        const clientId = "my-client-id";
        const issuer = `https://cognito-idp.us-east-1.amazonaws.com/us-east-1_123456`;
        const jwksUri = `https://public-keys.auth.elb.us-east-1.amazonaws.com`;
        const exp = 4000000000; // Use of a long expiry date

        const signedJwt1 = signJwt(
          {
            typ: "JWT",
            kid: keypair1.jwk.kid,
            alg: "ES256",
            iss: issuer,
            client: clientId,
            signer: albArn1,
            exp,
          },
          {
            hello: "world1",
            exp,
            iss: issuer,
          },
          keypair1.privateKey
        );

        const signedJwt2 = signJwt(
          {
            typ: "JWT",
            kid: keypair2.jwk.kid,
            alg: "ES256",
            iss: issuer,
            client: clientId,
            signer: albArn2,
            exp,
          },
          {
            hello: "world2",
            exp,
            iss: issuer,
          },
          keypair2.privateKey
        );

        const albVerifier = AlbJwtVerifier.create({
          issuer,
          clientId,
          albArn: [albArn1, albArn2],
          jwksUri,
        });

        albVerifier.cacheJwks(keypair1.jwks);
        albVerifier.cacheJwks(keypair2.jwks);
        expect.assertions(2);

        expect(await albVerifier.verify(signedJwt1)).toMatchObject({
          hello: "world1",
        });

        expect(await albVerifier.verify(signedJwt2)).toMatchObject({
          hello: "world2",
        });
      });

      test("cache jwks with multiple IDPs needs issuer", () => {
        const identityProviders = [
          {
            config: {
              albArn:
                "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-load-balancer/60dc6c495c0c9188",
              issuer:
                "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_qbc",
              clientId: "client1",
            },
            keypair: generateKeyPair({
              kid: "00000000-0000-0000-0000-000000000000",
              kty: "EC",
              alg: "ES256",
            }),
          },
          {
            config: {
              albArn:
                "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-load-balancer/",
              issuer:
                "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_def",
              clientId: "client2",
            },
            keypair: generateKeyPair({
              kid: "11111111-0000-0000-0000-000000000000",
              kty: "EC",
              alg: "ES256",
            }),
          },
        ];
        const verifier = AlbJwtVerifier.create(
          identityProviders.map((idp) => idp.config)
        );
        const issuer: any = undefined;
        const statement = () => verifier.cacheJwks(keypair.jwks, issuer);
        expect(statement).toThrow(
          new ParameterValidationError("issuer must be provided")
        );
      });
    });

    describe("jwksUri", () => {
      test("default jwksUri with alb arn in multiple regions error", async () => {
        const issuer = `https://cognito-idp.us-east-1.amazonaws.com/us-east-1_123456`;
        const albArn = [
          "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-load-balancer-1/50dc6c495c0c9188",
          "arn:aws:elasticloadbalancing:eu-west-2:123456789012:loadbalancer/app/my-load-balancer-2/901e7c495c0c9188",
        ];

        expect(() =>
          AlbJwtVerifier.create({
            albArn,
            issuer,
          })
        ).toThrow(
          new ParameterValidationError(
            "Unable to generate default jwksUri because multiple regions in ALB ARNs parameters found"
          )
        );
      });
    });
  });
});
