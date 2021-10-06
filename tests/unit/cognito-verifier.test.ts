import {
  generateKeyPair,
  signJwt,
  allowAllRealNetworkTraffic,
  disallowAllRealNetworkTraffic,
} from "./test-util";
import { decomposeJwt } from "../../src/jwt";
import { JwksCache, Jwks } from "../../src/jwk";
import { CognitoJwtVerifier } from "../../src/cognito-verifier";
import { AssertionError, ParameterValidationError } from "../../src/error";

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
        const decomposedJwt = decomposeJwt(signedJwt);
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
        ).toThrow(AssertionError);
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
        ).toThrow(AssertionError);
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
          AssertionError
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
        expect(() => verifier.verifySync(userJwt)).toThrow(AssertionError);
        expect(
          verifier.verifySync(userJwt, { groups: ["users"] })
        ).toMatchObject({
          token_use: "access",
          hello: "world",
        });
        expect(() => verifier.verifySync(noGroupJwt)).toThrow(AssertionError);
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
