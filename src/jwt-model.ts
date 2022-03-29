// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { JsonObject } from "./safe-json-parse.js";

export const supportedSignatureAlgorithms = [
  "RS256",
  "RS384",
  "RS512",
] as const;
export type SupportedSignatureAlgorithm =
  typeof supportedSignatureAlgorithms[number];

interface JwtHeaderStandardFields {
  alg?: SupportedSignatureAlgorithm | string; // algorithm: https://tools.ietf.org/html/rfc7517#section-4.4
  kid?: string; // key id: https://tools.ietf.org/html/rfc7517#section-4.5
}

export type JwtHeader = JwtHeaderStandardFields & JsonObject;

interface JwtPayloadStandardFields {
  exp?: number; // expires: https://tools.ietf.org/html/rfc7519#section-4.1.4
  iss?: string; // issuer: https://tools.ietf.org/html/rfc7519#section-4.1.1
  aud?: string | string[]; // audience: https://tools.ietf.org/html/rfc7519#section-4.1.3
  nbf?: number; // not before: https://tools.ietf.org/html/rfc7519#section-4.1.5
  iat?: number; // issued at: https://tools.ietf.org/html/rfc7519#section-4.1.6
  scope?: string; // scopes: https://tools.ietf.org/html/rfc6749#section-3.3
  jti?: string; // JWT ID: https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.7
}

export type JwtPayload = JwtPayloadStandardFields & JsonObject;

export interface Jwt {
  header: JwtHeader;
  payload: JwtPayload;
}

export type CognitoIdOrAccessTokenPayload<IssuerConfig, VerifyProps> =
  VerifyProps extends { tokenUse: null }
    ? CognitoJwtPayload
    : VerifyProps extends { tokenUse: "id" }
    ? CognitoIdTokenPayload
    : VerifyProps extends { tokenUse: "access" }
    ? CognitoAccessTokenPayload
    : IssuerConfig extends { tokenUse: "id" }
    ? CognitoIdTokenPayload
    : IssuerConfig extends { tokenUse: "access" }
    ? CognitoAccessTokenPayload
    : CognitoJwtPayload;

interface CognitoJwtFields {
  token_use: "access" | "id";
  "cognito:groups"?: string[];
  sub: string;
  iss: string;
  exp: number;
  iat: number;
  auth_time: number;
  jti: string;
  origin_jti: string;
}

export type CognitoJwtPayload = CognitoJwtFields & JsonObject;

interface CognitoIdTokenFields extends CognitoJwtFields {
  token_use: "id";
  aud: string;
  at_hash: string;
  "cognito:username": string;
  email_verified: boolean;
  phone_number_verified: boolean;
  identities: {
    userId: string;
    providerName: string;
    providerType: string;
    issuer: null;
    primary: string;
    dateCreated: string;
  }[];
  "cognito:roles": string[];
  "cognito:preferred_role": string;
}

export type CognitoIdTokenPayload = CognitoIdTokenFields & JsonObject;

interface CognitoAccessTokenFields extends CognitoJwtFields {
  token_use: "access";
  client_id: string;
  version: number;
  username: string;
  scope: string;
}

export type CognitoAccessTokenPayload = CognitoAccessTokenFields & JsonObject;

export interface CognitoJwt {
  header: JwtHeader;
  payload: CognitoAccessTokenPayload | CognitoIdTokenPayload;
}
