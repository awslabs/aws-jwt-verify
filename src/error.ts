// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

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

export class JwtInvalidClaimError extends JwtBaseError {}

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

/**
 * Assertion errors
 */

export class AssertionError extends JwtBaseError {}
