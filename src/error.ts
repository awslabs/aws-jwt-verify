// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { JwtHeader, JwtPayload } from "./jwt-model.js";

/**
 * Base Error for all other errors in this file
 */
export abstract class JwtBaseError extends Error {}

/**
 * Interface for an error that is raised because an actual value does not match with the expected value
 */
interface AssertionError extends JwtBaseError {
  failedAssertion: {
    actual: unknown;
    expected?: string | string[];
  };
}

/**
 * Constructor interface for AssertionError
 */
export interface AssertionErrorConstructor {
  new (
    msg: string,
    actual: unknown,
    expected?: string | string[]
  ): AssertionError;
}

/**
 * An error that is raised because an actual value does not match with the expected value
 */
export class FailedAssertionError extends JwtBaseError {
  failedAssertion: {
    actual: unknown;
    expected?: string | string[];
  };
  constructor(msg: string, actual: unknown, expected?: string | string[]) {
    super(msg);
    this.failedAssertion = {
      actual,
      expected,
    };
  }
}

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

export class JwtInvalidSignatureAlgorithmError extends FailedAssertionError {}

interface RawJwt {
  header: JwtHeader;
  payload: JwtPayload;
}

export abstract class JwtInvalidClaimError extends FailedAssertionError {
  public rawJwt?: RawJwt;
  public withRawJwt<T extends JwtInvalidClaimError>(
    this: T,
    { header, payload }: RawJwt
  ): T {
    this.rawJwt = {
      header,
      payload,
    };
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

export class JwksValidationError extends JwtBaseError {}

export class JwkValidationError extends JwtBaseError {}

export class JwtWithoutValidKidError extends JwtBaseError {}

export class KidNotFoundInJwksError extends JwtBaseError {}

export class WaitPeriodNotYetEndedJwkError extends JwtBaseError {}

export class JwksNotAvailableInCacheError extends JwtBaseError {}

export class JwkInvalidUseError extends FailedAssertionError {}

export class JwkInvalidKtyError extends FailedAssertionError {}

/**
 * HTTPS fetch errors
 */

export class FetchError extends JwtBaseError {
  constructor(uri: string, msg: unknown) {
    super(`Failed to fetch ${uri}: ${msg}`);
  }
}

export class NonRetryableFetchError extends FetchError {}
