// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { DecomposedJwt } from "./jwt.js";

export type AssertedClaim =
  | "payload.exp"
  | "payload.nbf"
  | "payload.iss"
  | "payload.aud"
  | "payload.scope"
  | "jwk.use"
  | "jwk.kty"
  | "header.alg"
  | "payload.client_id"
  | "payload.token_use"
  | "payload.cognito:groups";

interface AssertionError extends Error {
  failedAssertion: {
    claim: AssertedClaim;
    actual: unknown;
    expected?: string | string[];
  };
}

export interface AssertionErrorConstructor {
  new (
    msg: string,
    claim: AssertedClaim,
    actual: unknown,
    expected?: string | string[]
  ): AssertionError;
}

interface ExposeRawJwt<E extends JwtBaseError> {
  rawJwt?: DecomposedJwt;
  withRawJwt<T extends E>(this: T, rawJwt: DecomposedJwt): T;
}

export abstract class JwtBaseError extends Error {}

/**
 * JWT errors
 */

export class JwtParseError extends JwtBaseError {
  constructor(msg: string, error?: unknown) {
    const message = error != null ? `${msg}: ${error}` : msg;
    super(message);
  }
}

export class ParameterValidationError extends JwtBaseError {}

export class JwtInvalidSignatureError extends JwtBaseError {}

export abstract class FailedAssertionError
  extends JwtBaseError
  implements AssertionError
{
  failedAssertion: {
    claim: AssertedClaim;
    actual: unknown;
    expected?: string | string[];
  };
  constructor(
    msg: string,
    claim: AssertedClaim,
    actual: unknown,
    expected?: string | string[]
  ) {
    super(msg);
    this.failedAssertion = { claim, actual, expected };
  }
}

export class JwtInvalidSignatureAlgorithmError extends FailedAssertionError {}

export abstract class JwtInvalidClaimError
  extends FailedAssertionError
  implements ExposeRawJwt<JwtInvalidClaimError>
{
  public rawJwt?: DecomposedJwt;
  public withRawJwt<T extends JwtInvalidClaimError>(
    this: T,
    rawJwt: DecomposedJwt
  ): T {
    this.rawJwt = rawJwt;
    return this;
  }
}

export class JwtInvalidIssuerError extends JwtInvalidClaimError {}

export class JwtInvalidAudienceError extends JwtInvalidClaimError {}

export class JwtInvalidScopeError extends JwtInvalidClaimError {}

export class JwtExpiredError extends JwtInvalidClaimError {}

export class JwtNotBeforeError extends JwtInvalidClaimError {}

/**
 * Amazon Cognito specific erros
 */

export class CognitoJwtInvalidGroupError extends JwtInvalidClaimError {}

export class CognitoJwtInvalidTokenUseError extends JwtInvalidClaimError {}

export class CognitoJwtInvalidClientIdError extends JwtInvalidClaimError {}

/**
 * ASN.1 errors
 */

export class Asn1DecodingError extends JwtBaseError {}

/**
 * JWK errors
 */

export abstract class JwkError extends JwtBaseError {}

export class JwksValidationError extends JwkError {}

export class JwkValidationError extends JwkError {}

export class JwtWithoutValidKidError extends JwkError {}

export class KidNotFoundInJwksError extends JwkError {}

export class WaitPeriodNotYetEndedJwkError extends JwkError {}

export class JwksNotAvailableInCacheError extends JwkError {}

export abstract class JwkAssertionError
  extends JwkError
  implements AssertionError
{
  failedAssertion: {
    claim: AssertedClaim;
    actual: unknown;
    expected?: string | string[];
  };
  constructor(
    msg: string,
    claim: AssertedClaim,
    actual: unknown,
    expected?: string | string[]
  ) {
    super(msg);
    this.failedAssertion = { claim, actual, expected };
  }
}

export class JwkInvalidUseError extends JwkAssertionError {}

export class JwkInvalidKtyError extends JwkAssertionError {}

/**
 * HTTPS fetch errors
 */

export class FetchError extends JwtBaseError {
  constructor(uri: string, msg: unknown) {
    super(`Failed to fetch ${uri}: ${msg}`);
  }
}

export class NonRetryableFetchError extends FetchError {}
