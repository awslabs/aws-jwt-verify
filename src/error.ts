// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { DecomposedJwt } from "./jwt";

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

export class JwtInvalidSignatureError extends JwtBaseError {}

export class JwtExpiredError extends JwtBaseError {}

export class JwtNotBeforeError extends JwtBaseError {}

export class ParameterValidationError extends JwtBaseError {}

export abstract class JwtInvalidClaimError extends JwtBaseError {
  public failedAssertion: {
    name: string;
    actual: unknown;
    expected: string | string[];
  };
  public rawJwt?: DecomposedJwt;
  constructor(
    msg: string,
    name: string,
    actual: unknown,
    expected: string | string[]
  ) {
    super(msg);
    this.failedAssertion = { name, actual, expected };
  }
  public withRawJwt(rawJwt: DecomposedJwt): JwtInvalidClaimError {
    this.rawJwt = rawJwt;
    return this;
  }
}

export class JwtInvalidIssuerError extends JwtInvalidClaimError {}

export class JwtInvalidAudienceError extends JwtInvalidClaimError {}

export class JwtInvalidScopeError extends JwtInvalidClaimError {}

export class JwtInvalidSignatureAlgorithmError extends JwtInvalidClaimError {}

export class JwtInvalidJwkError extends JwtInvalidClaimError {}

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

export class JwksValidationError extends JwtBaseError {}

export class JwkValidationError extends JwtBaseError {}

export class JwtWithoutValidKidError extends JwtBaseError {}

export class KidNotFoundInJwksError extends JwtBaseError {}

export class WaitPeriodNotYetEndedJwkError extends JwtBaseError {}

export class JwksNotAvailableInCacheError extends JwtBaseError {}

/**
 * HTTPS fetch errors
 */

export class FetchError extends JwtBaseError {
  constructor(uri: string, msg: unknown) {
    super(`Failed to fetch ${uri}: ${msg}`);
  }
}

export class NonRetryableFetchError extends FetchError {}
