// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import * as outputs from "../outputs.json";
import { AlbJwtVerifier, CognitoJwtVerifier } from "aws-jwt-verify";
import {
  CognitoIdentityProviderClient,
  InitiateAuthCommand,
} from "@aws-sdk/client-cognito-identity-provider";
import * as alb from "./alb";

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
    UserPoolClientIdAlb: clientIdAlb,
    HttpApiEndpoint: httpApiEndpoint,
    ApplicationLoadBalancerArn: albArn,
  },
} = outputs;

let userSigninJWTs: { access: string; id: string };
let clientCredentialsJWTs: { access: string };
let albSigninJWTs: Awaited<
  ReturnType<(typeof alb)["callAlbAndSignInWithHostedUi"]>
>;
const cognitoVerifier = CognitoJwtVerifier.create({
  userPoolId,
});
const albJwtVerifier = AlbJwtVerifier.create({
  albArn,
  issuer: CognitoJwtVerifier.parseUserPoolId(userPoolId).issuer,
  clientId: clientIdAlb,
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
beforeAll(async () => {
  [userSigninJWTs, clientCredentialsJWTs, albSigninJWTs] = await Promise.all([
    getJWTsForUser(),
    getAccessTokenForClientCredentials(),
    alb.callAlbAndSignInWithHostedUi(),
    cognitoVerifier.hydrate(),
  ]);
});

async function getJWTsForUser() {
  const response = await CLIENT.send(SIGN_IN_AS_USER);
  return {
    access: response.AuthenticationResult!.AccessToken!,
    id: response.AuthenticationResult!.IdToken!,
  };
}

async function getAccessTokenForClientCredentials() {
  return fetch(`${hostedUIUrl}/oauth2/token`, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      authorization: `Basic ${Buffer.from(
        `${clientIdWithSecret}:${clientIdWithSecretValue}`
      ).toString("base64")}`,
    },
    body: Buffer.from(
      `grant_type=client_credentials&scope=${encodeURIComponent(scope)}`
    ),
  })
    .then((res) => res.json())
    .then(({ access_token }) => ({ access: access_token }));
}

test("Verify ID token for user: happy flow", async () => {
  return expect(
    cognitoVerifier.verify(userSigninJWTs.id, {
      clientId: userPoolWebClientId,
      tokenUse: "id",
    })
  ).resolves.toMatchObject({ email: "johndoe@example.com" });
});

test("Verify ID token for user: expired token", async () => {
  return expect(
    cognitoVerifier.verify(userSigninJWTs.id, {
      clientId: userPoolWebClientId,
      tokenUse: "id",
      graceSeconds: -3600 - 10, // token expires after 3600 seconds, subtract additional 10 seconds to account for any clock diff
    })
  ).rejects.toThrow("Token expired");
});

test("Verify Access token for user: happy flow", async () => {
  return expect(
    cognitoVerifier.verify(userSigninJWTs.access, {
      clientId: userPoolWebClientId,
      tokenUse: "access",
    })
  ).resolves.toMatchObject({ client_id: userPoolWebClientId });
});

test("Verify Access token for user: scope check", async () => {
  return expect(
    cognitoVerifier.verify(userSigninJWTs.access, {
      clientId: userPoolWebClientId,
      tokenUse: "access",
      scope: ["aws.cognito.signin.user.admin"],
    })
  ).resolves.toMatchObject({ client_id: userPoolWebClientId });
});

test("Verify Access token for client credentials: scope check", async () => {
  return expect(
    cognitoVerifier.verify(clientCredentialsJWTs.access, {
      clientId: clientIdWithSecret,
      tokenUse: "access",
      scope,
    })
  ).resolves.toMatchObject({ client_id: clientIdWithSecret });
});

test("HTTP API Lambda authorizer allows access with valid token", async () => {
  return expect(
    fetch(httpApiEndpoint, {
      headers: {
        authorization: userSigninJWTs.id,
      },
    }).then((res) => res.json())
  ).resolves.toMatchObject({ private: "content!" });
});

test("HTTP API Lambda authorizer does not allow access with wrong token", async () => {
  return expect(
    fetch(httpApiEndpoint, {
      headers: {
        authorization: userSigninJWTs.access,
      },
    }).then((res) => {
      if (!res.ok) throw new Error(`${res.status}`);
      return res;
    })
  ).rejects.toThrow("403");
});

test("Verify Cognito Access token from ALB", async () => {
  return expect(
    cognitoVerifier.verify(albSigninJWTs.cognitoAccessToken, {
      clientId: clientIdAlb,
      tokenUse: "access",
    })
  ).resolves.toMatchObject({ client_id: clientIdAlb });
});

test("Verify Data token from ALB", async () => {
  return expect(
    albJwtVerifier.verify(albSigninJWTs.albToken)
  ).resolves.toMatchObject({ email: username });
});
