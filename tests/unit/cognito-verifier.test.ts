import {
  generateKeyPair,
  signJwt,
  allowAllRealNetworkTraffic,
  disallowAllRealNetworkTraffic,
  mockHttpsUri,
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
    });

    describe("parseUserPoolId", () => {
      test("returns both standard and multi-region issuer formats", () => {
        const userPoolId = "us-east-1_abc123";
        const result = CognitoJwtVerifier.parseUserPoolId(userPoolId);

        expect(result.issuer).toBe(
          "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_abc123"
        );
        expect(result.jwksUri).toBe(
          "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_abc123/.well-known/jwks.json"
        );
        expect(result.multiRegionIssuer).toBe(
          "https://issuer.cognito-idp.us-east-1.amazonaws.com/us-east-1_abc123"
        );
        expect(result.multiRegionJwksUri).toBe(
          "https://issuer.cognito-idp.us-east-1.amazonaws.com/us-east-1_abc123/.well-known/jwks.json"
        );
      });

      test("handles various valid User Pool IDs", () => {
        const testCases = [
          {
            userPoolId: "us-west-2_XYZ789",
            expectedRegion: "us-west-2",
          },
          {
            userPoolId: "eu-west-1_TestPool",
            expectedRegion: "eu-west-1",
          },
          {
            userPoolId: "ap-southeast-1_Pool123",
            expectedRegion: "ap-southeast-1",
          },
        ];

        for (const { userPoolId, expectedRegion } of testCases) {
          const result = CognitoJwtVerifier.parseUserPoolId(userPoolId);

          expect(result.issuer).toBe(
            `https://cognito-idp.${expectedRegion}.amazonaws.com/${userPoolId}`
          );
          expect(result.multiRegionIssuer).toBe(
            `https://issuer.cognito-idp.${expectedRegion}.amazonaws.com/${userPoolId}`
          );
        }
      });

      test("handles GovCloud regions", () => {
        const userPoolId = "us-gov-west-1_GovPool123";
        const result = CognitoJwtVerifier.parseUserPoolId(userPoolId);

        expect(result.issuer).toBe(
          "https://cognito-idp.us-gov-west-1.amazonaws.com/us-gov-west-1_GovPool123"
        );
        expect(result.jwksUri).toBe(
          "https://cognito-idp.us-gov-west-1.amazonaws.com/us-gov-west-1_GovPool123/.well-known/jwks.json"
        );
        expect(result.multiRegionIssuer).toBe(
          "https://issuer.cognito-idp.us-gov-west-1.amazonaws.com/us-gov-west-1_GovPool123"
        );
        expect(result.multiRegionJwksUri).toBe(
          "https://issuer.cognito-idp.us-gov-west-1.amazonaws.com/us-gov-west-1_GovPool123/.well-known/jwks.json"
        );
      });
    });

    describe("parseIssuer", () => {
      test("parses valid standard issuer format", () => {
        const issuer =
          "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_abc123";
        const result = CognitoJwtVerifier.parseIssuer(issuer);

        expect(result).not.toBeNull();
        expect(result!.userPoolId).toBe("us-east-1_abc123");
        expect(result!.region).toBe("us-east-1");
        expect(result!.format).toBe("standard");
      });

      test("parses valid multi-region issuer format", () => {
        const issuer =
          "https://issuer.cognito-idp.us-east-1.amazonaws.com/us-east-1_abc123";
        const result = CognitoJwtVerifier.parseIssuer(issuer);

        expect(result).not.toBeNull();
        expect(result!.userPoolId).toBe("us-east-1_abc123");
        expect(result!.region).toBe("us-east-1");
        expect(result!.format).toBe("multiRegion");
      });

      test("returns null for invalid issuer formats", () => {
        const invalidIssuers = [
          "https://invalid.cognito-idp.us-east-1.amazonaws.com/us-east-1_abc123",
          "https://cognito-idp.invalid-region.amazonaws.com/us-east-1_abc123",
          "https://cognito-idp.us-east-1.amazonaws.com/invalid_pool",
          "http://cognito-idp.us-east-1.amazonaws.com/us-east-1_abc123", // http instead of https
          "https://cognito-idp.us-east-1.amazonaws.com", // missing user pool id
          "https://example.com/us-east-1_abc123", // wrong domain
          "", // empty string
          "not-a-url", // not a URL
        ];

        for (const issuer of invalidIssuers) {
          expect(CognitoJwtVerifier.parseIssuer(issuer)).toBeNull();
        }
      });

      test("returns null when region in issuer does not match region in userPoolId", () => {
        // Region mismatch: issuer says us-east-1 but userPoolId says us-west-2
        const issuer =
          "https://cognito-idp.us-east-1.amazonaws.com/us-west-2_abc123";
        const result = CognitoJwtVerifier.parseIssuer(issuer);

        expect(result).toBeNull();
      });

      test("parses GovCloud standard issuer format", () => {
        const issuer =
          "https://cognito-idp.us-gov-west-1.amazonaws.com/us-gov-west-1_GovPool123";
        const result = CognitoJwtVerifier.parseIssuer(issuer);

        expect(result).not.toBeNull();
        expect(result!.userPoolId).toBe("us-gov-west-1_GovPool123");
        expect(result!.region).toBe("us-gov-west-1");
        expect(result!.format).toBe("standard");
      });

      test("parses GovCloud multi-region issuer format", () => {
        const issuer =
          "https://issuer.cognito-idp.us-gov-west-1.amazonaws.com/us-gov-west-1_GovPool123";
        const result = CognitoJwtVerifier.parseIssuer(issuer);

        expect(result).not.toBeNull();
        expect(result!.userPoolId).toBe("us-gov-west-1_GovPool123");
        expect(result!.region).toBe("us-gov-west-1");
        expect(result!.format).toBe("multiRegion");
      });
    });

    describe("constructor registers both issuers", () => {
      test("single User Pool creates entries for both issuer formats", () => {
        const userPoolId = "us-east-1_abc123";
        const verifier = CognitoJwtVerifier.create({
          userPoolId,
          clientId: null,
          tokenUse: null,
        });

        // Verify both issuers work by caching JWKS and checking that
        // tokens with either issuer format can be verified
        verifier.cacheJwks(keypair.jwks);

        // Create and verify token with standard issuer
        const standardIssuer = `https://cognito-idp.us-east-1.amazonaws.com/${userPoolId}`;
        const standardJwt = signJwt(
          { kid: keypair.jwk.kid },
          {
            iss: standardIssuer,
            token_use: "access",
          },
          keypair.privateKey
        );
        expect(verifier.verifySync(standardJwt)).toMatchObject({
          iss: standardIssuer,
        });

        // Create and verify token with multi-region issuer
        const multiRegionIssuer = `https://issuer.cognito-idp.us-east-1.amazonaws.com/${userPoolId}`;
        const multiRegionJwt = signJwt(
          { kid: keypair.jwk.kid },
          {
            iss: multiRegionIssuer,
            token_use: "access",
          },
          keypair.privateKey
        );
        expect(verifier.verifySync(multiRegionJwt)).toMatchObject({
          iss: multiRegionIssuer,
        });
      });

      test("multiple User Pools create entries for all issuer formats", () => {
        const userPool1 = "us-east-1_pool1";
        const userPool2 = "us-west-2_pool2";

        const verifier = CognitoJwtVerifier.create([
          { userPoolId: userPool1, clientId: null, tokenUse: null },
          { userPoolId: userPool2, clientId: null, tokenUse: null },
        ]);

        // Cache JWKS for both pools
        verifier.cacheJwks(keypair.jwks, userPool1);
        verifier.cacheJwks(keypair.jwks, userPool2);

        // Test all four issuer combinations (2 pools × 2 formats)
        const testCases = [
          {
            userPoolId: userPool1,
            issuer: `https://cognito-idp.us-east-1.amazonaws.com/${userPool1}`,
          },
          {
            userPoolId: userPool1,
            issuer: `https://issuer.cognito-idp.us-east-1.amazonaws.com/${userPool1}`,
          },
          {
            userPoolId: userPool2,
            issuer: `https://cognito-idp.us-west-2.amazonaws.com/${userPool2}`,
          },
          {
            userPoolId: userPool2,
            issuer: `https://issuer.cognito-idp.us-west-2.amazonaws.com/${userPool2}`,
          },
        ];

        for (const { issuer } of testCases) {
          const jwt = signJwt(
            { kid: keypair.jwk.kid },
            {
              iss: issuer,
              token_use: "access",
            },
            keypair.privateKey
          );
          expect(verifier.verifySync(jwt)).toMatchObject({ iss: issuer });
        }
      });

      test("rejects token with issuer not matching any configured User Pool", () => {
        const userPoolId = "us-east-1_abc123";
        const verifier = CognitoJwtVerifier.create({
          userPoolId,
          clientId: null,
          tokenUse: null,
        });
        verifier.cacheJwks(keypair.jwks);

        // Create token with a different User Pool's issuer
        const wrongIssuer =
          "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_different";
        const jwt = signJwt(
          { kid: keypair.jwk.kid },
          {
            iss: wrongIssuer,
            token_use: "access",
          },
          keypair.privateKey
        );

        expect(() => verifier.verifySync(jwt)).toThrow(
          ParameterValidationError
        );
        expect(() => verifier.verifySync(jwt)).toThrow(
          `issuer not configured: ${wrongIssuer}`
        );
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
});

describe("integration tests - verification flows", () => {
  let keypair: ReturnType<typeof generateKeyPair>;

  beforeAll(() => {
    keypair = generateKeyPair();
    disallowAllRealNetworkTraffic();
  });

  afterAll(() => {
    allowAllRealNetworkTraffic();
  });

  afterEach(() => {
    // Clean up any pending mocks
    jest.clearAllMocks();
  });

  describe("verify with standard issuer format", () => {
    test("accepts JWT with standard issuer and fetches from correct JWKS endpoint", async () => {
      const userPoolId = "us-east-1_testPool";
      const { issuer, jwksUri } =
        CognitoJwtVerifier.parseUserPoolId(userPoolId);

      // Mock the standard JWKS endpoint
      mockHttpsUri(jwksUri, {
        responseStatus: 200,
        responsePayload: JSON.stringify(keypair.jwks),
      });

      const verifier = CognitoJwtVerifier.create({
        userPoolId,
        clientId: "testClient",
        tokenUse: "access",
      });

      const signedJwt = signJwt(
        { kid: keypair.jwk.kid },
        {
          iss: issuer,
          token_use: "access",
          client_id: "testClient",
        },
        keypair.privateKey
      );

      const result = await verifier.verify(signedJwt);

      expect(result).toMatchObject({
        iss: issuer,
        token_use: "access",
        client_id: "testClient",
      });
    });

    test("accepts ID token with standard issuer format", async () => {
      const userPoolId = "us-east-1_idTokenPool";
      const { issuer, jwksUri } =
        CognitoJwtVerifier.parseUserPoolId(userPoolId);

      mockHttpsUri(jwksUri, {
        responseStatus: 200,
        responsePayload: JSON.stringify(keypair.jwks),
      });

      const verifier = CognitoJwtVerifier.create({
        userPoolId,
        clientId: "idClient",
        tokenUse: "id",
      });

      const signedJwt = signJwt(
        { kid: keypair.jwk.kid },
        {
          iss: issuer,
          token_use: "id",
          aud: "idClient",
        },
        keypair.privateKey
      );

      const result = await verifier.verify(signedJwt);

      expect(result).toMatchObject({
        iss: issuer,
        token_use: "id",
        aud: "idClient",
      });
    });
  });

  describe("verify with multi-region issuer format", () => {
    test("accepts JWT with multi-region issuer and fetches from correct JWKS endpoint", async () => {
      const userPoolId = "us-east-1_multiRegion";
      const { multiRegionIssuer, multiRegionJwksUri } =
        CognitoJwtVerifier.parseUserPoolId(userPoolId);

      // Mock the multi-region JWKS endpoint
      mockHttpsUri(multiRegionJwksUri, {
        responseStatus: 200,
        responsePayload: JSON.stringify(keypair.jwks),
      });

      const verifier = CognitoJwtVerifier.create({
        userPoolId,
        clientId: "multiRegionClient",
        tokenUse: "access",
      });

      const signedJwt = signJwt(
        { kid: keypair.jwk.kid },
        {
          iss: multiRegionIssuer,
          token_use: "access",
          client_id: "multiRegionClient",
        },
        keypair.privateKey
      );

      const result = await verifier.verify(signedJwt);

      expect(result).toMatchObject({
        iss: multiRegionIssuer,
        token_use: "access",
        client_id: "multiRegionClient",
      });
    });

    test("accepts ID token with multi-region issuer format", async () => {
      const userPoolId = "eu-west-1_multiRegionId";
      const { multiRegionIssuer, multiRegionJwksUri } =
        CognitoJwtVerifier.parseUserPoolId(userPoolId);

      mockHttpsUri(multiRegionJwksUri, {
        responseStatus: 200,
        responsePayload: JSON.stringify(keypair.jwks),
      });

      const verifier = CognitoJwtVerifier.create({
        userPoolId,
        clientId: "multiIdClient",
        tokenUse: "id",
      });

      const signedJwt = signJwt(
        { kid: keypair.jwk.kid },
        {
          iss: multiRegionIssuer,
          token_use: "id",
          aud: "multiIdClient",
        },
        keypair.privateKey
      );

      const result = await verifier.verify(signedJwt);

      expect(result).toMatchObject({
        iss: multiRegionIssuer,
        token_use: "id",
        aud: "multiIdClient",
      });
    });
  });

  describe("rejection of invalid issuer formats", () => {
    test("rejects JWT with invalid issuer domain", async () => {
      const userPoolId = "us-east-1_validPool";
      const verifier = CognitoJwtVerifier.create({
        userPoolId,
        clientId: null,
        tokenUse: null,
      });
      verifier.cacheJwks(keypair.jwks);

      // Create JWT with invalid issuer domain
      const invalidIssuer =
        "https://invalid.cognito-idp.us-east-1.amazonaws.com/us-east-1_validPool";
      const signedJwt = signJwt(
        { kid: keypair.jwk.kid },
        {
          iss: invalidIssuer,
          token_use: "access",
        },
        keypair.privateKey
      );

      await expect(verifier.verify(signedJwt)).rejects.toThrow(
        ParameterValidationError
      );
      await expect(verifier.verify(signedJwt)).rejects.toThrow(
        `issuer not configured: ${invalidIssuer}`
      );
    });

    test("rejects JWT with mismatched User Pool ID in issuer", async () => {
      const userPoolId = "us-east-1_configuredPool";
      const verifier = CognitoJwtVerifier.create({
        userPoolId,
        clientId: null,
        tokenUse: null,
      });
      verifier.cacheJwks(keypair.jwks);

      // Create JWT with different User Pool ID in issuer
      const wrongPoolIssuer =
        "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_differentPool";
      const signedJwt = signJwt(
        { kid: keypair.jwk.kid },
        {
          iss: wrongPoolIssuer,
          token_use: "access",
        },
        keypair.privateKey
      );

      await expect(verifier.verify(signedJwt)).rejects.toThrow(
        ParameterValidationError
      );
      await expect(verifier.verify(signedJwt)).rejects.toThrow(
        `issuer not configured: ${wrongPoolIssuer}`
      );
    });

    test("rejects JWT with mismatched region in issuer", async () => {
      const userPoolId = "us-east-1_regionPool";
      const verifier = CognitoJwtVerifier.create({
        userPoolId,
        clientId: null,
        tokenUse: null,
      });
      verifier.cacheJwks(keypair.jwks);

      // Create JWT with different region in issuer
      const wrongRegionIssuer =
        "https://cognito-idp.us-west-2.amazonaws.com/us-east-1_regionPool";
      const signedJwt = signJwt(
        { kid: keypair.jwk.kid },
        {
          iss: wrongRegionIssuer,
          token_use: "access",
        },
        keypair.privateKey
      );

      await expect(verifier.verify(signedJwt)).rejects.toThrow(
        ParameterValidationError
      );
      await expect(verifier.verify(signedJwt)).rejects.toThrow(
        `issuer not configured: ${wrongRegionIssuer}`
      );
    });

    test("rejects JWT with non-Cognito issuer", async () => {
      const userPoolId = "us-east-1_cognitoPool";
      const verifier = CognitoJwtVerifier.create({
        userPoolId,
        clientId: null,
        tokenUse: null,
      });
      verifier.cacheJwks(keypair.jwks);

      // Create JWT with completely different issuer
      const nonCognitoIssuer = "https://example.com/us-east-1_cognitoPool";
      const signedJwt = signJwt(
        { kid: keypair.jwk.kid },
        {
          iss: nonCognitoIssuer,
          token_use: "access",
        },
        keypair.privateKey
      );

      await expect(verifier.verify(signedJwt)).rejects.toThrow(
        ParameterValidationError
      );
      await expect(verifier.verify(signedJwt)).rejects.toThrow(
        `issuer not configured: ${nonCognitoIssuer}`
      );
    });
  });

  describe("multi-pool configuration", () => {
    test("verifies tokens from multiple User Pools with standard issuer format", async () => {
      const pool1 = "us-east-1_pool1";
      const pool2 = "us-west-2_pool2";

      const keypair1 = generateKeyPair({ kty: "RSA", kid: "key1" });
      const keypair2 = generateKeyPair({ kty: "RSA", kid: "key2" });

      const parsed1 = CognitoJwtVerifier.parseUserPoolId(pool1);
      const parsed2 = CognitoJwtVerifier.parseUserPoolId(pool2);

      // Mock JWKS endpoints for both pools (standard format)
      mockHttpsUri(parsed1.jwksUri, {
        responseStatus: 200,
        responsePayload: JSON.stringify(keypair1.jwks),
      });
      mockHttpsUri(parsed2.jwksUri, {
        responseStatus: 200,
        responsePayload: JSON.stringify(keypair2.jwks),
      });

      const verifier = CognitoJwtVerifier.create([
        { userPoolId: pool1, clientId: "client1", tokenUse: "access" },
        { userPoolId: pool2, clientId: "client2", tokenUse: "access" },
      ]);

      // Verify token from pool1
      const jwt1 = signJwt(
        { kid: keypair1.jwk.kid },
        {
          iss: parsed1.issuer,
          token_use: "access",
          client_id: "client1",
        },
        keypair1.privateKey
      );
      const result1 = await verifier.verify(jwt1);
      expect(result1).toMatchObject({ iss: parsed1.issuer });

      // Verify token from pool2
      const jwt2 = signJwt(
        { kid: keypair2.jwk.kid },
        {
          iss: parsed2.issuer,
          token_use: "access",
          client_id: "client2",
        },
        keypair2.privateKey
      );
      const result2 = await verifier.verify(jwt2);
      expect(result2).toMatchObject({ iss: parsed2.issuer });
    });

    test("verifies tokens from multiple User Pools with multi-region issuer format", async () => {
      const pool1 = "us-east-1_multiPool1";
      const pool2 = "eu-west-1_multiPool2";

      const keypair1 = generateKeyPair({ kty: "RSA", kid: "multiKey1" });
      const keypair2 = generateKeyPair({ kty: "RSA", kid: "multiKey2" });

      const parsed1 = CognitoJwtVerifier.parseUserPoolId(pool1);
      const parsed2 = CognitoJwtVerifier.parseUserPoolId(pool2);

      // Mock JWKS endpoints for both pools (multi-region format)
      mockHttpsUri(parsed1.multiRegionJwksUri, {
        responseStatus: 200,
        responsePayload: JSON.stringify(keypair1.jwks),
      });
      mockHttpsUri(parsed2.multiRegionJwksUri, {
        responseStatus: 200,
        responsePayload: JSON.stringify(keypair2.jwks),
      });

      const verifier = CognitoJwtVerifier.create([
        { userPoolId: pool1, clientId: "multiClient1", tokenUse: "access" },
        { userPoolId: pool2, clientId: "multiClient2", tokenUse: "access" },
      ]);

      // Verify token from pool1 with multi-region issuer
      const jwt1 = signJwt(
        { kid: keypair1.jwk.kid },
        {
          iss: parsed1.multiRegionIssuer,
          token_use: "access",
          client_id: "multiClient1",
        },
        keypair1.privateKey
      );
      const result1 = await verifier.verify(jwt1);
      expect(result1).toMatchObject({ iss: parsed1.multiRegionIssuer });

      // Verify token from pool2 with multi-region issuer
      const jwt2 = signJwt(
        { kid: keypair2.jwk.kid },
        {
          iss: parsed2.multiRegionIssuer,
          token_use: "access",
          client_id: "multiClient2",
        },
        keypair2.privateKey
      );
      const result2 = await verifier.verify(jwt2);
      expect(result2).toMatchObject({ iss: parsed2.multiRegionIssuer });
    });

    test("verifies tokens with mixed issuer formats from multiple pools", async () => {
      const pool1 = "us-east-1_mixedPool1";
      const pool2 = "ap-southeast-1_mixedPool2";

      const keypair1 = generateKeyPair({ kty: "RSA", kid: "mixedKey1" });
      const keypair2 = generateKeyPair({ kty: "RSA", kid: "mixedKey2" });

      const parsed1 = CognitoJwtVerifier.parseUserPoolId(pool1);
      const parsed2 = CognitoJwtVerifier.parseUserPoolId(pool2);

      // Mock JWKS endpoints - pool1 uses standard, pool2 uses multi-region
      mockHttpsUri(parsed1.jwksUri, {
        responseStatus: 200,
        responsePayload: JSON.stringify(keypair1.jwks),
      });
      mockHttpsUri(parsed2.multiRegionJwksUri, {
        responseStatus: 200,
        responsePayload: JSON.stringify(keypair2.jwks),
      });

      const verifier = CognitoJwtVerifier.create([
        { userPoolId: pool1, clientId: "mixedClient1", tokenUse: "access" },
        { userPoolId: pool2, clientId: "mixedClient2", tokenUse: "access" },
      ]);

      // Verify token from pool1 with standard issuer
      const jwt1 = signJwt(
        { kid: keypair1.jwk.kid },
        {
          iss: parsed1.issuer,
          token_use: "access",
          client_id: "mixedClient1",
        },
        keypair1.privateKey
      );
      const result1 = await verifier.verify(jwt1);
      expect(result1).toMatchObject({ iss: parsed1.issuer });

      // Verify token from pool2 with multi-region issuer
      const jwt2 = signJwt(
        { kid: keypair2.jwk.kid },
        {
          iss: parsed2.multiRegionIssuer,
          token_use: "access",
          client_id: "mixedClient2",
        },
        keypair2.privateKey
      );
      const result2 = await verifier.verify(jwt2);
      expect(result2).toMatchObject({ iss: parsed2.multiRegionIssuer });
    });

    test("rejects token from unconfigured pool in multi-pool setup", async () => {
      const pool1 = "us-east-1_configPool1";
      const pool2 = "us-west-2_configPool2";

      const verifier = CognitoJwtVerifier.create([
        { userPoolId: pool1, clientId: null, tokenUse: null },
        { userPoolId: pool2, clientId: null, tokenUse: null },
      ]);

      // Cache JWKS for configured pools
      verifier.cacheJwks(keypair.jwks, pool1);
      verifier.cacheJwks(keypair.jwks, pool2);

      // Try to verify token from unconfigured pool
      const unconfiguredIssuer =
        "https://cognito-idp.eu-central-1.amazonaws.com/eu-central-1_unconfigured";
      const jwt = signJwt(
        { kid: keypair.jwk.kid },
        {
          iss: unconfiguredIssuer,
          token_use: "access",
        },
        keypair.privateKey
      );

      await expect(verifier.verify(jwt)).rejects.toThrow(
        ParameterValidationError
      );
      await expect(verifier.verify(jwt)).rejects.toThrow(
        `issuer not configured: ${unconfiguredIssuer}`
      );
    });
  });
});

describe("hydrate() and caching behavior", () => {
  let keypair: ReturnType<typeof generateKeyPair>;

  beforeAll(() => {
    keypair = generateKeyPair();
    disallowAllRealNetworkTraffic();
  });

  afterAll(() => {
    allowAllRealNetworkTraffic();
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe("hydrate() fetches from both endpoints", () => {
    test("hydrate() fetches JWKS from both standard and multi-region endpoints for single User Pool", async () => {
      const userPoolId = "us-east-1_hydratePool";
      const { issuer, jwksUri, multiRegionIssuer, multiRegionJwksUri } =
        CognitoJwtVerifier.parseUserPoolId(userPoolId);

      // Mock both JWKS endpoints
      mockHttpsUri(jwksUri, {
        responseStatus: 200,
        responsePayload: JSON.stringify(keypair.jwks),
      });
      mockHttpsUri(multiRegionJwksUri, {
        responseStatus: 200,
        responsePayload: JSON.stringify(keypair.jwks),
      });

      const verifier = CognitoJwtVerifier.create({
        userPoolId,
        clientId: null,
        tokenUse: null,
      });

      await verifier.hydrate();

      // Verify both endpoints were called by checking that tokens can be verified synchronously
      // (which requires the JWKS to be cached)
      const standardJwt = signJwt(
        { kid: keypair.jwk.kid },
        { iss: issuer, token_use: "access" },
        keypair.privateKey
      );
      expect(verifier.verifySync(standardJwt)).toMatchObject({ iss: issuer });

      const multiRegionJwt = signJwt(
        { kid: keypair.jwk.kid },
        { iss: multiRegionIssuer, token_use: "access" },
        keypair.privateKey
      );
      expect(verifier.verifySync(multiRegionJwt)).toMatchObject({
        iss: multiRegionIssuer,
      });
    });

    test("hydrate() fetches JWKS from all endpoints for multiple User Pools", async () => {
      const pool1 = "us-east-1_hydratePool1";
      const pool2 = "eu-west-1_hydratePool2";

      const parsed1 = CognitoJwtVerifier.parseUserPoolId(pool1);
      const parsed2 = CognitoJwtVerifier.parseUserPoolId(pool2);

      // Mock all four JWKS endpoints (2 pools × 2 formats)
      mockHttpsUri(parsed1.jwksUri, {
        responseStatus: 200,
        responsePayload: JSON.stringify(keypair.jwks),
      });
      mockHttpsUri(parsed1.multiRegionJwksUri, {
        responseStatus: 200,
        responsePayload: JSON.stringify(keypair.jwks),
      });
      mockHttpsUri(parsed2.jwksUri, {
        responseStatus: 200,
        responsePayload: JSON.stringify(keypair.jwks),
      });
      mockHttpsUri(parsed2.multiRegionJwksUri, {
        responseStatus: 200,
        responsePayload: JSON.stringify(keypair.jwks),
      });

      const verifier = CognitoJwtVerifier.create([
        { userPoolId: pool1, clientId: null, tokenUse: null },
        { userPoolId: pool2, clientId: null, tokenUse: null },
      ]);

      await verifier.hydrate();

      // Verify all endpoints were called by checking that tokens can be verified synchronously
      const testCases = [
        { issuer: parsed1.issuer },
        { issuer: parsed1.multiRegionIssuer },
        { issuer: parsed2.issuer },
        { issuer: parsed2.multiRegionIssuer },
      ];

      for (const { issuer } of testCases) {
        const jwt = signJwt(
          { kid: keypair.jwk.kid },
          { iss: issuer, token_use: "access" },
          keypair.privateKey
        );
        expect(verifier.verifySync(jwt)).toMatchObject({ iss: issuer });
      }
    });

    test("after hydrate(), tokens with either issuer format can be verified synchronously", async () => {
      const userPoolId = "us-east-1_hydrateVerify";
      const { issuer, jwksUri, multiRegionIssuer, multiRegionJwksUri } =
        CognitoJwtVerifier.parseUserPoolId(userPoolId);

      // Mock both JWKS endpoints
      mockHttpsUri(jwksUri, {
        responseStatus: 200,
        responsePayload: JSON.stringify(keypair.jwks),
      });
      mockHttpsUri(multiRegionJwksUri, {
        responseStatus: 200,
        responsePayload: JSON.stringify(keypair.jwks),
      });

      const verifier = CognitoJwtVerifier.create({
        userPoolId,
        clientId: null,
        tokenUse: null,
      });

      await verifier.hydrate();

      // Verify token with standard issuer synchronously
      const standardJwt = signJwt(
        { kid: keypair.jwk.kid },
        { iss: issuer, token_use: "access" },
        keypair.privateKey
      );
      expect(verifier.verifySync(standardJwt)).toMatchObject({ iss: issuer });

      // Verify token with multi-region issuer synchronously
      const multiRegionJwt = signJwt(
        { kid: keypair.jwk.kid },
        { iss: multiRegionIssuer, token_use: "access" },
        keypair.privateKey
      );
      expect(verifier.verifySync(multiRegionJwt)).toMatchObject({
        iss: multiRegionIssuer,
      });
    });
  });

  describe("cacheJwks() caches for both issuers", () => {
    test("cacheJwks() with User Pool ID caches JWKS for both issuer formats", () => {
      const userPoolId = "us-east-1_cachePool";
      const { issuer, multiRegionIssuer } =
        CognitoJwtVerifier.parseUserPoolId(userPoolId);

      const verifier = CognitoJwtVerifier.create({
        userPoolId,
        clientId: null,
        tokenUse: null,
      });

      // Cache JWKS once
      verifier.cacheJwks(keypair.jwks);

      // Verify token with standard issuer can be verified synchronously
      const standardJwt = signJwt(
        { kid: keypair.jwk.kid },
        { iss: issuer, token_use: "access" },
        keypair.privateKey
      );
      expect(verifier.verifySync(standardJwt)).toMatchObject({ iss: issuer });

      // Verify token with multi-region issuer can be verified synchronously
      const multiRegionJwt = signJwt(
        { kid: keypair.jwk.kid },
        { iss: multiRegionIssuer, token_use: "access" },
        keypair.privateKey
      );
      expect(verifier.verifySync(multiRegionJwt)).toMatchObject({
        iss: multiRegionIssuer,
      });
    });

    test("cacheJwks() with explicit User Pool ID in multi-pool setup caches for both formats", () => {
      const pool1 = "us-east-1_cacheMulti1";
      const pool2 = "us-west-2_cacheMulti2";

      const parsed1 = CognitoJwtVerifier.parseUserPoolId(pool1);
      const parsed2 = CognitoJwtVerifier.parseUserPoolId(pool2);

      const verifier = CognitoJwtVerifier.create([
        { userPoolId: pool1, clientId: null, tokenUse: null },
        { userPoolId: pool2, clientId: null, tokenUse: null },
      ]);

      // Cache JWKS for pool1
      verifier.cacheJwks(keypair.jwks, pool1);

      // Verify tokens from pool1 with both formats work synchronously
      const standardJwt1 = signJwt(
        { kid: keypair.jwk.kid },
        { iss: parsed1.issuer, token_use: "access" },
        keypair.privateKey
      );
      expect(verifier.verifySync(standardJwt1)).toMatchObject({
        iss: parsed1.issuer,
      });

      const multiRegionJwt1 = signJwt(
        { kid: keypair.jwk.kid },
        { iss: parsed1.multiRegionIssuer, token_use: "access" },
        keypair.privateKey
      );
      expect(verifier.verifySync(multiRegionJwt1)).toMatchObject({
        iss: parsed1.multiRegionIssuer,
      });

      // Cache JWKS for pool2
      verifier.cacheJwks(keypair.jwks, pool2);

      // Verify tokens from pool2 with both formats work synchronously
      const standardJwt2 = signJwt(
        { kid: keypair.jwk.kid },
        { iss: parsed2.issuer, token_use: "access" },
        keypair.privateKey
      );
      expect(verifier.verifySync(standardJwt2)).toMatchObject({
        iss: parsed2.issuer,
      });

      const multiRegionJwt2 = signJwt(
        { kid: keypair.jwk.kid },
        { iss: parsed2.multiRegionIssuer, token_use: "access" },
        keypair.privateKey
      );
      expect(verifier.verifySync(multiRegionJwt2)).toMatchObject({
        iss: parsed2.multiRegionIssuer,
      });
    });
  });

  describe("cache isolation", () => {
    test("cache miss on standard endpoint does not affect multi-region cache", async () => {
      const userPoolId = "us-east-1_isolationPool";
      const { issuer, jwksUri, multiRegionIssuer, multiRegionJwksUri } =
        CognitoJwtVerifier.parseUserPoolId(userPoolId);

      // Create a keypair for multi-region and a different one for standard
      const multiRegionKeypair = generateKeyPair({
        kty: "RSA",
        kid: "multiKey",
      });
      const standardKeypair = generateKeyPair({
        kty: "RSA",
        kid: "standardKey",
      });

      // Mock multi-region endpoint with its keypair
      mockHttpsUri(multiRegionJwksUri, {
        responseStatus: 200,
        responsePayload: JSON.stringify(multiRegionKeypair.jwks),
      });

      const verifier = CognitoJwtVerifier.create({
        userPoolId,
        clientId: null,
        tokenUse: null,
      });

      // First, verify a token with multi-region issuer (this will fetch and cache multi-region JWKS)
      const multiRegionJwt = signJwt(
        { kid: multiRegionKeypair.jwk.kid },
        { iss: multiRegionIssuer, token_use: "access" },
        multiRegionKeypair.privateKey
      );
      const result1 = await verifier.verify(multiRegionJwt);
      expect(result1).toMatchObject({ iss: multiRegionIssuer });

      // Now mock the standard endpoint with a different keypair
      mockHttpsUri(jwksUri, {
        responseStatus: 200,
        responsePayload: JSON.stringify(standardKeypair.jwks),
      });

      // Verify a token with standard issuer (this will fetch standard JWKS separately)
      const standardJwt = signJwt(
        { kid: standardKeypair.jwk.kid },
        { iss: issuer, token_use: "access" },
        standardKeypair.privateKey
      );
      const result2 = await verifier.verify(standardJwt);
      expect(result2).toMatchObject({ iss: issuer });

      // Verify that multi-region cache is still intact by verifying another multi-region token synchronously
      const anotherMultiRegionJwt = signJwt(
        { kid: multiRegionKeypair.jwk.kid },
        { iss: multiRegionIssuer, token_use: "access", sub: "user2" },
        multiRegionKeypair.privateKey
      );
      expect(verifier.verifySync(anotherMultiRegionJwt)).toMatchObject({
        iss: multiRegionIssuer,
        sub: "user2",
      });
    });

    test("cache miss on multi-region endpoint does not affect standard cache", async () => {
      const userPoolId = "us-east-1_isolationPool2";
      const { issuer, jwksUri, multiRegionIssuer, multiRegionJwksUri } =
        CognitoJwtVerifier.parseUserPoolId(userPoolId);

      // Create different keypairs for each endpoint
      const standardKeypair = generateKeyPair({ kty: "RSA", kid: "stdKey" });
      const multiRegionKeypair = generateKeyPair({ kty: "RSA", kid: "mrKey" });

      // Mock standard endpoint first
      mockHttpsUri(jwksUri, {
        responseStatus: 200,
        responsePayload: JSON.stringify(standardKeypair.jwks),
      });

      const verifier = CognitoJwtVerifier.create({
        userPoolId,
        clientId: null,
        tokenUse: null,
      });

      // First, verify a token with standard issuer (this will fetch and cache standard JWKS)
      const standardJwt = signJwt(
        { kid: standardKeypair.jwk.kid },
        { iss: issuer, token_use: "access" },
        standardKeypair.privateKey
      );
      const result1 = await verifier.verify(standardJwt);
      expect(result1).toMatchObject({ iss: issuer });

      // Now mock the multi-region endpoint
      mockHttpsUri(multiRegionJwksUri, {
        responseStatus: 200,
        responsePayload: JSON.stringify(multiRegionKeypair.jwks),
      });

      // Verify a token with multi-region issuer (this will fetch multi-region JWKS separately)
      const multiRegionJwt = signJwt(
        { kid: multiRegionKeypair.jwk.kid },
        { iss: multiRegionIssuer, token_use: "access" },
        multiRegionKeypair.privateKey
      );
      const result2 = await verifier.verify(multiRegionJwt);
      expect(result2).toMatchObject({ iss: multiRegionIssuer });

      // Verify that standard cache is still intact by verifying another standard token synchronously
      const anotherStandardJwt = signJwt(
        { kid: standardKeypair.jwk.kid },
        { iss: issuer, token_use: "access", sub: "user3" },
        standardKeypair.privateKey
      );
      expect(verifier.verifySync(anotherStandardJwt)).toMatchObject({
        iss: issuer,
        sub: "user3",
      });
    });

    test("each endpoint maintains independent cache entries", async () => {
      const userPoolId = "us-east-1_independentCache";
      const { issuer, jwksUri, multiRegionIssuer, multiRegionJwksUri } =
        CognitoJwtVerifier.parseUserPoolId(userPoolId);

      // Create different keypairs for each endpoint
      const standardKeypair = generateKeyPair({ kty: "RSA", kid: "indStdKey" });
      const multiRegionKeypair = generateKeyPair({
        kty: "RSA",
        kid: "indMrKey",
      });

      // Mock both endpoints with different keypairs
      mockHttpsUri(jwksUri, {
        responseStatus: 200,
        responsePayload: JSON.stringify(standardKeypair.jwks),
      });
      mockHttpsUri(multiRegionJwksUri, {
        responseStatus: 200,
        responsePayload: JSON.stringify(multiRegionKeypair.jwks),
      });

      const verifier = CognitoJwtVerifier.create({
        userPoolId,
        clientId: null,
        tokenUse: null,
      });

      // Hydrate to fetch both JWKS
      await verifier.hydrate();

      // Verify standard token works with standard keypair
      const standardJwt = signJwt(
        { kid: standardKeypair.jwk.kid },
        { iss: issuer, token_use: "access" },
        standardKeypair.privateKey
      );
      expect(verifier.verifySync(standardJwt)).toMatchObject({ iss: issuer });

      // Verify multi-region token works with multi-region keypair
      const multiRegionJwt = signJwt(
        { kid: multiRegionKeypair.jwk.kid },
        { iss: multiRegionIssuer, token_use: "access" },
        multiRegionKeypair.privateKey
      );
      expect(verifier.verifySync(multiRegionJwt)).toMatchObject({
        iss: multiRegionIssuer,
      });

      // Verify that using wrong keypair for wrong issuer fails
      // Standard token signed with multi-region keypair should fail
      const wrongStandardJwt = signJwt(
        { kid: multiRegionKeypair.jwk.kid },
        { iss: issuer, token_use: "access" },
        multiRegionKeypair.privateKey
      );
      expect(() => verifier.verifySync(wrongStandardJwt)).toThrow();

      // Multi-region token signed with standard keypair should fail
      const wrongMultiRegionJwt = signJwt(
        { kid: standardKeypair.jwk.kid },
        { iss: multiRegionIssuer, token_use: "access" },
        standardKeypair.privateKey
      );
      expect(() => verifier.verifySync(wrongMultiRegionJwt)).toThrow();
    });
  });
});
