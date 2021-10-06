import * as outputs from "../outputs.json";
import { CognitoJwtVerifier } from "../../../cognito-verifier";
import { fetchJson } from "../../../https";
import { JsonObject } from "../../../safe-json-parse";
import {
  CognitoIdentityProviderClient,
  InitiateAuthCommand,
} from "@aws-sdk/client-cognito-identity-provider";

const {
  AwsJwtCognitoTestStack: {
    UserPoolUser: username,
    UserPoolUserPassword: password,
    UserPoolRegion: region,
    UserPoolClientId: userPoolWebClientId,
    UserPoolId: userPoolId,
    ResourceServerWithScope: scope,
    HostedUIUrl: hostedUIUrl,
    UserPoolClientWithSecretClientId: clientIdWithSecret,
    UserPoolClientWithSecretValue: clientIdWithSecretValue,
    HttpApiEndpoint: httpApiEndpoint,
  },
} = outputs;

let userSigninJWTs: Promise<{ access: string; id: string }>;
let clientCredentialsJWTs: Promise<{ access: string }>;
const cognitoVerifier = CognitoJwtVerifier.create({
  userPoolId,
});
const CLIENT = new CognitoIdentityProviderClient({ region });
const SIGN_IN_AS_USER = new InitiateAuthCommand({
  ClientId: userPoolWebClientId,
  AuthFlow: "USER_PASSWORD_AUTH",
  AuthParameters: {
    USERNAME: username,
    PASSWORD: password,
  },
});
beforeAll(() => {
  userSigninJWTs = getJWTsForUser();
  clientCredentialsJWTs = getAccessTokenForClientCredentials();
});

async function getJWTsForUser() {
  const response = await CLIENT.send(SIGN_IN_AS_USER);
  return {
    access: response.AuthenticationResult!.AccessToken!,
    id: response.AuthenticationResult!.IdToken!,
  };
}

async function getAccessTokenForClientCredentials() {
  return fetchJson(
    `${hostedUIUrl}/oauth2/token`,
    {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        authorization: `Basic ${Buffer.from(
          `${clientIdWithSecret}:${clientIdWithSecretValue}`
        ).toString("base64")}`,
      },
    },
    Buffer.from(
      `grant_type=client_credentials&scope=${encodeURIComponent(scope)}`
    )
  ).then((res) => ({ access: (res as JsonObject)["access_token"] as string }));
}

test("Verify ID token for user: happy flow", async () => {
  const JWTs = await userSigninJWTs;
  return expect(
    cognitoVerifier.verify(JWTs.id, {
      clientId: userPoolWebClientId,
      tokenUse: "id",
    })
  ).resolves.toMatchObject({ email: "johndoe@example.com" });
});

test("Verify ID token for user: expired token", async () => {
  const JWTs = await userSigninJWTs;
  return expect(
    cognitoVerifier.verify(JWTs.id, {
      clientId: userPoolWebClientId,
      tokenUse: "id",
      graceSeconds: -3600 - 10, // token expires after 3600 seconds, subtract additional 10 seconds to account for any clock diff
    })
  ).rejects.toThrow("Token expired");
});

test("Verify Access token for user: happy flow", async () => {
  const JWTs = await userSigninJWTs;
  return expect(
    cognitoVerifier.verify(JWTs.access, {
      clientId: userPoolWebClientId,
      tokenUse: "access",
    })
  ).resolves.toMatchObject({ client_id: userPoolWebClientId });
});

test("Verify Access token for user: scope check", async () => {
  const JWTs = await userSigninJWTs;
  return expect(
    cognitoVerifier.verify(JWTs.access, {
      clientId: userPoolWebClientId,
      tokenUse: "access",
      scope: ["aws.cognito.signin.user.admin"],
    })
  ).resolves.toMatchObject({ client_id: userPoolWebClientId });
});

test("Verify Access token for client credentials: scope check", async () => {
  const JWTs = await clientCredentialsJWTs;
  return expect(
    cognitoVerifier.verify(JWTs.access, {
      clientId: clientIdWithSecret,
      tokenUse: "access",
      scope,
    })
  ).resolves.toMatchObject({ client_id: clientIdWithSecret });
});

test("HTTP API Lambda authorizer allows access with valid token", async () => {
  const JWTs = await userSigninJWTs;
  return expect(
    fetchJson(httpApiEndpoint, {
      headers: {
        authorization: JWTs.id,
      },
    })
  ).resolves.toMatchObject({ private: "content!" });
});

test("HTTP API Lambda authorizer does not allow access with wrong token", async () => {
  const JWTs = await userSigninJWTs;
  return expect(
    fetchJson(httpApiEndpoint, {
      headers: {
        authorization: JWTs.access,
      },
    })
  ).rejects.toThrow("403");
});
