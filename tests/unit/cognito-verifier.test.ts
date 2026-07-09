import {
  generateKeyPair,
  signJwt,
  allowAllRealNetworkTraffic,
  disallowAllRealNetworkTraffic,
} from "./test-util";
import { decomposeUnverifiedJwt } from "../../src/jwt";
import { JwksCache, Jwks } from "../../src/jwk";
import { CognitoJwtVerifier } from "../../src/cognito-verifier";
import {
  ParameterValidationError,
  CognitoJwtInvalidTokenUseError,
  CognitoJwtInvalidGroupError,
  JwtInvalidClaimError,
} from "../../src/error";

describe("unit tests cognito verifier", () => {
  let keypair: ReturnType<typeof generateKeyPair>;
  beforeAll(() => {
    keypair = generateKeyPair();
    disallowAllRealNetworkTraffic();
  });
  afterAll(() => {
    allowAllRealNetworkTraffic();
  });

  describe("CognitoJwtVerifier", () => {
    describe("verify", () => {
      test("happy flow", async () => {
        const userPoolId = "us-east-1_123456";
        const { issuer } = CognitoJwtVerifier.parseUserPoolId(userPoolId);
        const signedJwt = signJwt(
          { kid: keypair.jwk.kid },
          {
            hello: "world",
            iss: issuer,
            token_use: "access",
          },
          keypair.privateKey
        );
        const decomposedJwt = decomposeUnverifiedJwt(signedJwt);
        const customJwtCheck = jest.fn();
        const cognitoVerifier = CognitoJwtVerifier.create({
          userPoolId,
          customJwtCheck,
        });
        cognitoVerifier.cacheJwks(keypair.jwks);
        expect.assertions(2);
        expect(
          await cognitoVerifier.verify(signedJwt, {
            clientId: null,
            tokenUse: null,
            groups: null,
            scope: null,
          })
        ).toMatchObject({ hello: "world" });
        expect(customJwtCheck).toHaveBeenCalledWith({
          header: decomposedJwt.header,
          payload: decomposedJwt.payload,
          jwk: keypair.jwk,
        });
      });
    });
    describe("includeRawJwtInErrors", () => {
      test("verify - flag set at statement level", () => {
        const userPoolId = "us-east-1_123456";
        const { issuer } = CognitoJwtVerifier.parseUserPoolId(userPoolId);
        const header = { alg: "RS256", kid: keypair.jwk.kid };
        const payload = {
          hello: "world",
          iss: issuer,
          token_use: "access",
        };
        const signedJwt = signJwt(header, payload, keypair.privateKey);
        const cognitoVerifier = CognitoJwtVerifier.create({
          userPoolId,
        });
        cognitoVerifier.cacheJwks(keypair.jwks);
        const statement = () =>
          cognitoVerifier.verify(signedJwt, {
            clientId: null,
            tokenUse: "id",
            includeRawJwtInErrors: true,
          });
        expect.assertions(2);
        expect(statement).rejects.toThrow(CognitoJwtInvalidTokenUseError);
        return statement().catch((err) => {
          expect((err as JwtInvalidClaimError).rawJwt).toMatchObject({
            header,
            payload,
          });
        });
      });
      test("verify - flag set at verifier level", () => {
        const userPoolId = "us-east-1_123456";
        const { issuer } = CognitoJwtVerifier.parseUserPoolId(userPoolId);
        const header = { alg: "RS256", kid: keypair.jwk.kid };
        const payload = {
          hello: "world",
          iss: issuer,
          token_use: "access",
        };
        const signedJwt = signJwt(header, payload, keypair.privateKey);
        const cognitoVerifier = CognitoJwtVerifier.create({
          userPoolId,
          includeRawJwtInErrors: true,
        });
        cognitoVerifier.cacheJwks(keypair.jwks);
        const statement = () =>
          cognitoVerifier.verify(signedJwt, {
            clientId: null,
            tokenUse: "id",
          });
        expect.assertions(2);
        expect(statement).rejects.toThrow(CognitoJwtInvalidTokenUseError);
        return statement().catch((err) => {
          expect((err as JwtInvalidClaimError).rawJwt).toMatchObject({
            header,
            payload,
          });
        });
      });
      test("verify - flag NOT set", () => {
        const userPoolId = "us-east-1_123456";
        const { issuer } = CognitoJwtVerifier.parseUserPoolId(userPoolId);
        const header = { alg: "RS256", kid: keypair.jwk.kid };
        const payload = {
          hello: "world",
          iss: issuer,
          token_use: "access",
        };
        const signedJwt = signJwt(header, payload, keypair.privateKey);
        const cognitoVerifier = CognitoJwtVerifier.create({
          userPoolId,
        });
        cognitoVerifier.cacheJwks(keypair.jwks);
        const statement = () =>
          cognitoVerifier.verify(signedJwt, {
            clientId: null,
            tokenUse: "id",
          });
        expect.assertions(2);
        expect(statement).rejects.toThrow(CognitoJwtInvalidTokenUseError);
        return statement().catch((err) => {
          expect((err as JwtInvalidClaimError).rawJwt).toBe(undefined);
        });
      });
      test("verifySync - flag set at verifier level", () => {
        const userPoolId = "us-east-1_123456";
        const { issuer } = CognitoJwtVerifier.parseUserPoolId(userPoolId);
        const header = { alg: "RS256", kid: keypair.jwk.kid };
        const payload = {
          hello: "world",
          iss: issuer,
          token_use: "access",
        };
        const signedJwt = signJwt(header, payload, keypair.privateKey);
        const cognitoVerifier = CognitoJwtVerifier.create({
          userPoolId,
          includeRawJwtInErrors: true,
        });
        cognitoVerifier.cacheJwks(keypair.jwks);
        const statement = () =>
          cognitoVerifier.verifySync(signedJwt, {
            clientId: null,
            tokenUse: "id",
          });
        expect.assertions(2);
        expect(statement).toThrow(CognitoJwtInvalidTokenUseError);
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
        const userPoolId = "us-east-1_123456";
        const { issuer } = CognitoJwtVerifier.parseUserPoolId(userPoolId);
        const header = { alg: "RS256", kid: keypair.jwk.kid };
        const payload = {
          hello: "world",
          iss: issuer,
          token_use: "access",
        };
        const signedJwt = signJwt(header, payload, keypair.privateKey);
        const cognitoVerifier = CognitoJwtVerifier.create({
          userPoolId,
        });
        cognitoVerifier.cacheJwks(keypair.jwks);
        const statement = () =>
          cognitoVerifier.verifySync(signedJwt, {
            clientId: null,
            tokenUse: "id",
          });
        expect.assertions(2);
        expect(statement).toThrow(CognitoJwtInvalidTokenUseError);
        try {
          statement();
        } catch (err) {
          expect((err as JwtInvalidClaimError).rawJwt).toEqual(undefined);
        }
      });
    });
    describe("verifySync", () => {
      test("happy flow", () => {
        const userPoolId = "us-east-1_123456";
        const { issuer } = CognitoJwtVerifier.parseUserPoolId(userPoolId);
        const signedJwt = signJwt(
          { kid: keypair.jwk.kid },
          {
            hello: "world",
            iss: issuer,
            token_use: "access",
          },
          keypair.privateKey
        );
        const cognitoVerifier = CognitoJwtVerifier.create({ userPoolId });
        cognitoVerifier.cacheJwks(keypair.jwks);
        expect(
          cognitoVerifier.verifySync(signedJwt, {
            clientId: null,
            tokenUse: null,
            groups: null,
            scope: null,
          })
        ).toMatchObject({ hello: "world" });
      });
      test("id token check", () => {
        const verifier = CognitoJwtVerifier.create({
          userPoolId: "us-east-1_abc",
          clientId: "myclientid",
          tokenUse: "id",
        });
        verifier.cacheJwks(keypair.jwks);
        const signedIdJwt = signJwt(
          { kid: keypair.jwk.kid },
          {
            token_use: "id",
            hello: "world",
            iss: "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_abc",
            aud: "myclientid",
          },
          keypair.privateKey
        );
        expect(verifier.verifySync(signedIdJwt)).toMatchObject({
          token_use: "id",
          hello: "world",
        });
        expect(() =>
          verifier.verifySync(signedIdJwt, { tokenUse: "access" })
        ).toThrow(CognitoJwtInvalidTokenUseError);
      });
      test("access token check", () => {
        const verifier = CognitoJwtVerifier.create({
          userPoolId: "us-east-1_abc",
          clientId: "myclientid",
          tokenUse: "access",
        });
        verifier.cacheJwks(keypair.jwks);
        const signedAccessJwt = signJwt(
          { kid: keypair.jwk.kid },
          {
            token_use: "access",
            hello: "world",
            iss: "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_abc",
            client_id: "myclientid",
          },
          keypair.privateKey
        );
        expect(verifier.verifySync(signedAccessJwt)).toMatchObject({
          token_use: "access",
          hello: "world",
        });
        expect(() =>
          verifier.verifySync(signedAccessJwt, { tokenUse: "id" })
        ).toThrow(CognitoJwtInvalidTokenUseError);
      });
      test("missing token use", () => {
        const verifier = CognitoJwtVerifier.create({
          userPoolId: "us-east-1_abc",
          clientId: "myclientid",
          tokenUse: "access",
        });
        verifier.cacheJwks(keypair.jwks);
        const signedAccessJwt = signJwt(
          { kid: keypair.jwk.kid },
          {
            hello: "world",
            iss: "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_abc",
            client_id: "myclientid",
          },
          keypair.privateKey
        );
        expect(() => verifier.verifySync(signedAccessJwt)).toThrow(
          "Missing Token use. Expected one of: id, access"
        );
        expect(() => verifier.verifySync(signedAccessJwt)).toThrow(
          CognitoJwtInvalidTokenUseError
        );
      });
      test("Cognito group check works", () => {
        const verifier = CognitoJwtVerifier.create({
          userPoolId: "us-east-1_abc",
          clientId: "myclientid",
          tokenUse: "access",
          groups: ["admin"],
        });
        verifier.cacheJwks(keypair.jwks);
        const adminJwt = signJwt(
          { kid: keypair.jwk.kid },
          {
            token_use: "access",
            hello: "world",
            iss: "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_abc",
            client_id: "myclientid",
            "cognito:groups": ["users", "others", "admin"],
          },
          keypair.privateKey
        );
        const userJwt = signJwt(
          { kid: keypair.jwk.kid },
          {
            token_use: "access",
            hello: "world",
            iss: "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_abc",
            client_id: "myclientid",
            "cognito:groups": ["users"],
          },
          keypair.privateKey
        );
        const noGroupJwt = signJwt(
          { kid: keypair.jwk.kid },
          {
            token_use: "access",
            hello: "world",
            iss: "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_abc",
            client_id: "myclientid",
          },
          keypair.privateKey
        );
        expect(verifier.verifySync(adminJwt)).toMatchObject({
          token_use: "access",
          hello: "world",
        });
        expect(() => verifier.verifySync(userJwt)).toThrow(
          CognitoJwtInvalidGroupError
        );
        expect(
          verifier.verifySync(userJwt, { groups: ["users"] })
        ).toMatchObject({
          token_use: "access",
          hello: "world",
        });
        expect(() => verifier.verifySync(noGroupJwt)).toThrow(
          CognitoJwtInvalidGroupError
        );
      });
      test("clientId undefined", () => {
        const verifier = CognitoJwtVerifier.create({
          userPoolId: "us-east-1_abc",
          clientId: undefined as unknown as null,
          tokenUse: null,
        });
        verifier.cacheJwks(keypair.jwks);
        const signedAccessJwt = signJwt(
          { kid: keypair.jwk.kid },
          {
            token_use: "access",
            hello: "world",
            iss: "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_abc",
            client_id: "myclientid",
          },
          keypair.privateKey
        );
        expect.assertions(2);
        expect(() => verifier.verifySync(signedAccessJwt)).toThrow(
          "clientId must be provided or set to null explicitly"
        );
        expect(() => verifier.verifySync(signedAccessJwt)).toThrow(
          ParameterValidationError
        );
      });
      test("tokenUse undefined", () => {
        const verifier = CognitoJwtVerifier.create({
          userPoolId: "us-east-1_abc",
          clientId: "myclientid",
          tokenUse: undefined as unknown as null,
        });
        verifier.cacheJwks(keypair.jwks);
        const signedAccessJwt = signJwt(
          { kid: keypair.jwk.kid },
          {
            token_use: "access",
            hello: "world",
            iss: "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_abc",
            client_id: "myclientid",
          },
          keypair.privateKey
        );
        expect.assertions(2);
        expect(() => verifier.verifySync(signedAccessJwt)).toThrow(
          "tokenUse must be provided or set to null explicitly"
        );
        expect(() => verifier.verifySync(signedAccessJwt)).toThrow(
          ParameterValidationError
        );
      });
      test("Invalid User Pool ID", () => {
        expect(() =>
          CognitoJwtVerifier.parseUserPoolId("foo-central-bar_cfE3xfsaf")
        ).toThrow("Invalid Cognito User Pool ID");
      });

      test("parseUserPoolId with EU Sovereign Cloud region (eusc)", () => {
        const userPoolId = "eusc-de-east-1_abc123";
        const { issuer, jwksUri } =
          CognitoJwtVerifier.parseUserPoolId(userPoolId);
        expect(issuer).toBe(
          "https://cognito-idp.eusc-de-east-1.amazonaws.com/eusc-de-east-1_abc123"
        );
        expect(jwksUri).toBe(
          "https://cognito-idp.eusc-de-east-1.amazonaws.com/eusc-de-east-1_abc123/.well-known/jwks.json"
        );
      });

      test("parseUserPoolId with GovCloud region", () => {
        const userPoolId = "us-gov-west-1_abc123";
        const { issuer, jwksUri } =
          CognitoJwtVerifier.parseUserPoolId(userPoolId);
        expect(issuer).toBe(
          "https://cognito-idp.us-gov-west-1.amazonaws.com/us-gov-west-1_abc123"
        );
        expect(jwksUri).toBe(
          "https://cognito-idp.us-gov-west-1.amazonaws.com/us-gov-west-1_abc123/.well-known/jwks.json"
        );
      });

      test("verify JWT with EU Sovereign Cloud user pool", () => {
        const userPoolId = "eusc-de-east-1_abc123";
        const issuer =
          "https://cognito-idp.eusc-de-east-1.amazonaws.com/eusc-de-east-1_abc123";
        const signedJwt = signJwt(
          { kid: keypair.jwk.kid },
          {
            hello: "world",
            iss: issuer,
            token_use: "access",
            client_id: "test-client",
          },
          keypair.privateKey
        );
        const cognitoVerifier = CognitoJwtVerifier.create({
          userPoolId,
          tokenUse: "access",
          clientId: "test-client",
        });
        cognitoVerifier.cacheJwks(keypair.jwks);
        expect(cognitoVerifier.verifySync(signedJwt)).toMatchObject({
          hello: "world",
          iss: issuer,
        });
      });

      test("verify JWT with GovCloud user pool", () => {
        const userPoolId = "us-gov-west-1_abc123";
        const issuer =
          "https://cognito-idp.us-gov-west-1.amazonaws.com/us-gov-west-1_abc123";
        const signedJwt = signJwt(
          { kid: keypair.jwk.kid },
          {
            hello: "world",
            iss: issuer,
            token_use: "access",
            client_id: "test-client",
          },
          keypair.privateKey
        );
        const cognitoVerifier = CognitoJwtVerifier.create({
          userPoolId,
          tokenUse: "access",
          clientId: "test-client",
        });
        cognitoVerifier.cacheJwks(keypair.jwks);
        expect(cognitoVerifier.verifySync(signedJwt)).toMatchObject({
          hello: "world",
          iss: issuer,
        });
      });

      test("parseUserPoolId with region format (default)", () => {
        const userPoolId = "us-east-1_123456";
        const { issuer, jwksUri } =
          CognitoJwtVerifier.parseUserPoolId(userPoolId);
        expect(issuer).toBe(
          "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_123456"
        );
        expect(jwksUri).toBe(
          "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_123456/.well-known/jwks.json"
        );
      });

      test("parseUserPoolId with global format from JWT", () => {
        const userPoolId = "us-east-1_123456";
        const jwtIssuer =
          "https://issuer-cognito-idp.us-east-1.amazonaws.com/us-east-1_123456";
        const { issuer, jwksUri } = CognitoJwtVerifier.parseUserPoolId(
          userPoolId,
          jwtIssuer
        );
        expect(issuer).toBe(
          "https://issuer-cognito-idp.us-east-1.amazonaws.com/us-east-1_123456"
        );
        expect(jwksUri).toBe(
          "https://issuer-cognito-idp.us-east-1.amazonaws.com/us-east-1_123456/.well-known/jwks.json"
        );
      });

      test("parseUserPoolId with region format from JWT", () => {
        const userPoolId = "us-east-1_123456";
        const jwtIssuer =
          "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_123456";
        const { issuer, jwksUri } = CognitoJwtVerifier.parseUserPoolId(
          userPoolId,
          jwtIssuer
        );
        expect(issuer).toBe(
          "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_123456"
        );
        expect(jwksUri).toBe(
          "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_123456/.well-known/jwks.json"
        );
      });

      test("verify JWT with global issuer format", () => {
        const userPoolId = "us-east-1_123456";
        const globalIssuer =
          "https://issuer-cognito-idp.us-east-1.amazonaws.com/us-east-1_123456";
        const signedJwt = signJwt(
          { kid: keypair.jwk.kid },
          {
            hello: "world",
            iss: globalIssuer,
            token_use: "access",
            client_id: "test-client",
          },
          keypair.privateKey
        );
        const cognitoVerifier = CognitoJwtVerifier.create({
          userPoolId,
          tokenUse: "access",
          clientId: "test-client",
        });

        // The JWKS cache is keyed by jwksUri, so we need to cache for the global format URL
        // In practice, this would be fetched automatically on first verification
        const globalFormatJwksUri = `${globalIssuer}/.well-known/jwks.json`;
        cognitoVerifier["jwksCache"].addJwks(globalFormatJwksUri, keypair.jwks);

        expect.assertions(1);
        expect(cognitoVerifier.verifySync(signedJwt)).toMatchObject({
          hello: "world",
          iss: globalIssuer,
        });
      });

      test("verify JWT with region issuer format", async () => {
        const userPoolId = "us-east-1_123456";
        const regionIssuer =
          "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_123456";
        const signedJwt = signJwt(
          { kid: keypair.jwk.kid },
          {
            hello: "world",
            iss: regionIssuer,
            token_use: "access",
            client_id: "test-client",
          },
          keypair.privateKey
        );
        const cognitoVerifier = CognitoJwtVerifier.create({
          userPoolId,
          tokenUse: "access",
          clientId: "test-client",
        });
        cognitoVerifier.cacheJwks(keypair.jwks);
        expect.assertions(1);
        expect(await cognitoVerifier.verify(signedJwt)).toMatchObject({
          hello: "world",
          iss: regionIssuer,
        });
      });
    });
  });

  describe("CognitoJwtVerifier with multiple user pools", () => {
    describe("verifySync", () => {
      test("happy flow", async () => {
        const identityProviders = [
          {
            config: {
              userPoolId: "us-east-1_abc",
              clientId: "client1",
              tokenUse: "id" as const,
            },
            keypair: generateKeyPair(),
          },
          {
            config: {
              userPoolId: "us-east-1_def",
              clientId: "client2",
              tokenUse: "access" as const,
            },
            keypair: generateKeyPair(),
          },
        ];
        const verifier = CognitoJwtVerifier.create(
          identityProviders.map((idp) => idp.config)
        );

        expect.assertions(identityProviders.length);
        for (const idp of identityProviders) {
          verifier.cacheJwks(idp.keypair.jwks, idp.config.userPoolId);
          const signedJwt = signJwt(
            { kid: idp.keypair.jwk.kid },
            {
              aud:
                idp.config.tokenUse === "id" ? idp.config.clientId : undefined,
              iss: CognitoJwtVerifier.parseUserPoolId(idp.config.userPoolId)
                .issuer,
              hello: "world",
              token_use: idp.config.tokenUse,
              client_id:
                idp.config.tokenUse === "access"
                  ? idp.config.clientId
                  : undefined,
            },
            idp.keypair.privateKey
          );
          expect(verifier.verify(signedJwt)).resolves.toMatchObject({
            hello: "world",
          });
        }
      });
      test("cache jwks with multiple IDPs needs userPoolId", () => {
        const identityProviders = [
          {
            config: {
              userPoolId: "us-east-1_abc",
              clientId: "client1",
              tokenUse: "id" as const,
            },
            keypair: generateKeyPair(),
          },
          {
            config: {
              userPoolId: "us-east-1_def",
              clientId: "client2",
              tokenUse: "access" as const,
            },
            keypair: generateKeyPair(),
          },
        ];
        const verifier = CognitoJwtVerifier.create(
          identityProviders.map((idp) => idp.config)
        );
        const emptyUserPoolId: any = undefined;
        const statement = () =>
          verifier.cacheJwks(keypair.jwks, emptyUserPoolId);
        expect(statement).toThrow(
          new ParameterValidationError("userPoolId must be provided")
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
        const userPoolId = "us-east-1_abc";
        const { jwksUri } = CognitoJwtVerifier.parseUserPoolId(userPoolId);
        const verifier = CognitoJwtVerifier.create(
          {
            userPoolId,
            tokenUse: "id",
          },
          { jwksCache: customJwksCache }
        );
        verifier.cacheJwks(keypair.jwks);
        expect(customJwksCache.addJwks).toHaveBeenCalledWith(
          jwksUri,
          keypair.jwks
        );
      });
    });
  });

  describe("CognitoJwtVerifier with Multi-Region Replication (MRR)", () => {
    test("Updated issuer: verify JWT from any region without additionalRegions", () => {
      // With Updated issuer, the iss claim always uses the primary region,
      // so no additionalRegions is needed for MRR
      const userPoolId = "us-east-1_abcd12345";
      const updatedIssuer =
        "https://issuer-cognito-idp.us-east-1.amazonaws.com/us-east-1_abcd12345";

      // JWT issued from a replica region, but with Updated issuer format
      // (the issuer URL uses the primary region regardless of which region issues it)
      const signedJwt = signJwt(
        { kid: keypair.jwk.kid },
        {
          hello: "world",
          iss: updatedIssuer,
          token_use: "access",
          client_id: "test-client",
        },
        keypair.privateKey
      );

      // No additionalRegions needed!
      const cognitoVerifier = CognitoJwtVerifier.create({
        userPoolId,
        tokenUse: "access",
        clientId: "test-client",
      });
      cognitoVerifier.cacheJwks(keypair.jwks);

      expect(cognitoVerifier.verifySync(signedJwt)).toMatchObject({
        hello: "world",
        iss: updatedIssuer,
      });
    });

    test("verify JWT from replica region with additionalRegions", () => {
      // Primary user pool in us-east-1, replicated to us-west-2
      const userPoolId = "us-east-1_abcd12345";
      const replicaIssuer =
        "https://cognito-idp.us-west-2.amazonaws.com/us-east-1_abcd12345";

      const signedJwt = signJwt(
        { kid: keypair.jwk.kid },
        {
          hello: "world",
          iss: replicaIssuer,
          token_use: "access",
          client_id: "test-client",
        },
        keypair.privateKey
      );

      const cognitoVerifier = CognitoJwtVerifier.create({
        userPoolId,
        tokenUse: "access",
        clientId: "test-client",
        additionalRegions: ["us-west-2"],
      });
      cognitoVerifier.cacheJwks(keypair.jwks);

      expect(cognitoVerifier.verifySync(signedJwt)).toMatchObject({
        hello: "world",
        iss: replicaIssuer,
      });
    });

    test("verify JWT from primary region still works with additionalRegions", () => {
      const userPoolId = "us-east-1_abcd12345";
      const primaryIssuer =
        "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_abcd12345";

      const signedJwt = signJwt(
        { kid: keypair.jwk.kid },
        {
          hello: "world",
          iss: primaryIssuer,
          token_use: "access",
          client_id: "test-client",
        },
        keypair.privateKey
      );

      const cognitoVerifier = CognitoJwtVerifier.create({
        userPoolId,
        tokenUse: "access",
        clientId: "test-client",
        additionalRegions: ["us-west-2"],
      });
      cognitoVerifier.cacheJwks(keypair.jwks);

      expect(cognitoVerifier.verifySync(signedJwt)).toMatchObject({
        hello: "world",
        iss: primaryIssuer,
      });
    });

    test("reject JWT with Updated issuer format from non-primary region", () => {
      const userPoolId = "us-east-1_abcd12345";
      // The Updated issuer format always uses the primary region in the iss claim,
      // regardless of which replica issued the token. A token claiming to be from
      // a replica region in Updated format should be rejected.
      const replicaUpdatedIssuer =
        "https://issuer-cognito-idp.us-west-2.amazonaws.com/us-east-1_abcd12345";

      const signedJwt = signJwt(
        { kid: keypair.jwk.kid },
        {
          hello: "world",
          iss: replicaUpdatedIssuer,
          token_use: "access",
          client_id: "test-client",
        },
        keypair.privateKey
      );

      const cognitoVerifier = CognitoJwtVerifier.create({
        userPoolId,
        tokenUse: "access",
        clientId: "test-client",
        additionalRegions: ["us-west-2"],
      });
      cognitoVerifier.cacheJwks(keypair.jwks);

      expect(() => cognitoVerifier.verifySync(signedJwt)).toThrow(
        "issuer not configured"
      );
    });

    test("reject JWT from non-configured region", () => {
      const userPoolId = "us-east-1_abcd12345";
      // JWT issued from eu-west-1 which is NOT in additionalRegions
      const unconfiguredIssuer =
        "https://cognito-idp.eu-west-1.amazonaws.com/us-east-1_abcd12345";

      const signedJwt = signJwt(
        { kid: keypair.jwk.kid },
        {
          hello: "world",
          iss: unconfiguredIssuer,
          token_use: "access",
          client_id: "test-client",
        },
        keypair.privateKey
      );

      const cognitoVerifier = CognitoJwtVerifier.create({
        userPoolId,
        tokenUse: "access",
        clientId: "test-client",
        additionalRegions: ["us-west-2"],
      });
      cognitoVerifier.cacheJwks(keypair.jwks);

      expect(() => cognitoVerifier.verifySync(signedJwt)).toThrow(
        "issuer not configured"
      );
    });

    test("multiple additionalRegions", () => {
      const userPoolId = "us-east-1_abcd12345";

      // Replicated to both us-west-2 and eu-west-1
      const cognitoVerifier = CognitoJwtVerifier.create({
        userPoolId,
        tokenUse: "access",
        clientId: "test-client",
        additionalRegions: ["us-west-2", "eu-west-1"],
      });
      cognitoVerifier.cacheJwks(keypair.jwks);

      // Verify from us-west-2
      const signedJwtWest2 = signJwt(
        { kid: keypair.jwk.kid },
        {
          hello: "from-west-2",
          iss: "https://cognito-idp.us-west-2.amazonaws.com/us-east-1_abcd12345",
          token_use: "access",
          client_id: "test-client",
        },
        keypair.privateKey
      );
      expect(cognitoVerifier.verifySync(signedJwtWest2)).toMatchObject({
        hello: "from-west-2",
      });

      // Verify from eu-west-1
      const signedJwtEuWest1 = signJwt(
        { kid: keypair.jwk.kid },
        {
          hello: "from-eu-west-1",
          iss: "https://cognito-idp.eu-west-1.amazonaws.com/us-east-1_abcd12345",
          token_use: "access",
          client_id: "test-client",
        },
        keypair.privateKey
      );
      expect(cognitoVerifier.verifySync(signedJwtEuWest1)).toMatchObject({
        hello: "from-eu-west-1",
      });
    });

    test("multi-pool verifier with additionalRegions", () => {
      const identityProviders = [
        {
          config: {
            userPoolId: "us-east-1_abc",
            clientId: "client1",
            tokenUse: "access" as const,
            additionalRegions: ["us-west-2"],
          },
          keypair: generateKeyPair(),
        },
        {
          config: {
            userPoolId: "eu-west-1_def",
            clientId: "client2",
            tokenUse: "access" as const,
            additionalRegions: ["eu-central-1"],
          },
          keypair: generateKeyPair(),
        },
      ];

      const verifier = CognitoJwtVerifier.create(
        identityProviders.map((idp) => idp.config)
      );

      // Cache JWKS for both pools
      for (const idp of identityProviders) {
        verifier.cacheJwks(idp.keypair.jwks, idp.config.userPoolId);
      }

      // Verify JWT from us-east-1_abc in replica region us-west-2
      const signedJwt1 = signJwt(
        { kid: identityProviders[0].keypair.jwk.kid },
        {
          hello: "pool1-replica",
          iss: "https://cognito-idp.us-west-2.amazonaws.com/us-east-1_abc",
          token_use: "access",
          client_id: "client1",
        },
        identityProviders[0].keypair.privateKey
      );
      expect(verifier.verifySync(signedJwt1)).toMatchObject({
        hello: "pool1-replica",
      });

      // Verify JWT from eu-west-1_def in replica region eu-central-1
      const signedJwt2 = signJwt(
        { kid: identityProviders[1].keypair.jwk.kid },
        {
          hello: "pool2-replica",
          iss: "https://cognito-idp.eu-central-1.amazonaws.com/eu-west-1_def",
          token_use: "access",
          client_id: "client2",
        },
        identityProviders[1].keypair.privateKey
      );
      expect(verifier.verifySync(signedJwt2)).toMatchObject({
        hello: "pool2-replica",
      });
    });

    test("parseUserPoolId with regionOverride", () => {
      const userPoolId = "us-east-1_abcd12345";
      const { issuer, jwksUri } = CognitoJwtVerifier.parseUserPoolId(
        userPoolId,
        undefined,
        "us-west-2"
      );
      expect(issuer).toBe(
        "https://cognito-idp.us-west-2.amazonaws.com/us-east-1_abcd12345"
      );
      expect(jwksUri).toBe(
        "https://cognito-idp.us-west-2.amazonaws.com/us-east-1_abcd12345/.well-known/jwks.json"
      );
    });

    test("parseUserPoolId with regionOverride and Updated issuer format", () => {
      const userPoolId = "us-east-1_abcd12345";
      const jwtIssuer =
        "https://issuer-cognito-idp.us-west-2.amazonaws.com/us-east-1_abcd12345";
      const { issuer, jwksUri } = CognitoJwtVerifier.parseUserPoolId(
        userPoolId,
        jwtIssuer,
        "us-west-2"
      );
      expect(issuer).toBe(
        "https://issuer-cognito-idp.us-west-2.amazonaws.com/us-east-1_abcd12345"
      );
      expect(jwksUri).toBe(
        "https://issuer-cognito-idp.us-west-2.amazonaws.com/us-east-1_abcd12345/.well-known/jwks.json"
      );
    });

    test("extractRegion", () => {
      expect(CognitoJwtVerifier.extractRegion("us-east-1_abc123")).toBe(
        "us-east-1"
      );
      expect(CognitoJwtVerifier.extractRegion("eu-west-1_xyz789")).toBe(
        "eu-west-1"
      );
      expect(CognitoJwtVerifier.extractRegion("us-gov-west-1_abc123")).toBe(
        "us-gov-west-1"
      );
      expect(CognitoJwtVerifier.extractRegion("eusc-de-east-1_abc123")).toBe(
        "eusc-de-east-1"
      );
      expect(() => CognitoJwtVerifier.extractRegion("invalid-pool-id")).toThrow(
        "Invalid Cognito User Pool ID"
      );
    });

    test("duplicate region in additionalRegions is handled gracefully", () => {
      const userPoolId = "us-east-1_abcd12345";
      // Including us-east-1 (the primary) in additionalRegions shouldn't cause issues
      expect(() =>
        CognitoJwtVerifier.create({
          userPoolId,
          tokenUse: "access",
          clientId: "test-client",
          additionalRegions: ["us-east-1", "us-west-2"],
        })
      ).not.toThrow();
    });
  });
});
