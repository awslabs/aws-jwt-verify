// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  assertStringArrayContainsString,
  assertStringArraysOverlap,
} from "./assert.js";
import { JwtHeader, JwtPayload } from "./jwt-model.js";
import { safeJsonParse, isJsonObject } from "./safe-json-parse.js";
import {
  JwtExpiredError,
  JwtNotBeforeError,
  JwtInvalidIssuerError,
  JwtInvalidAudienceError,
  JwtInvalidScopeError,
  JwtParseError,
  ParameterValidationError,
} from "./error.js";
import { nodeWebCompat } from "#node-web-compat";
import { AsAsync } from "./typing-util.js";

/**
 * Type for a generic key object, at runtime either the Node.js or WebCrypto concrete key object is used
 */
export type GenericKeyObject = object;

/**
 * Verify (synchronously) the JSON Web Signature (JWS) of a JWT
 * https://datatracker.ietf.org/doc/html/rfc7515
 *
 * @param keyObject: the keyobject (representing the public key) in native crypto format
 * @param alg: the JWS algorithm that was used to create the JWS (e.g. RS256)
 * @param jwsSigningInput: the input for which the JWS was created, i.e. that what was signed
 * @param signature: the JSON Web Signature (JWS)
 * @returns boolean: true if the JWS is valid, or false otherwise
 */
export type JwsVerificationFunctionSync<T extends string> = (props: {
  keyObject: GenericKeyObject;
  alg: T;
  jwsSigningInput: string;
  signature: string;
}) => boolean;

/**
 * Verify (asynchronously) the JSON Web Signature (JWS) of a JWT
 * https://datatracker.ietf.org/doc/html/rfc7515
 *
 * @param keyObject: the keyobject (representing the public key) in native crypto format
 * @param alg: the JWS algorithm that was used to create the JWS (e.g. RS256)
 * @param jwsSigningInput: the input for which the JWS was created, i.e. that what was signed
 * @param signature: the JSON Web Signature (JWS)
 * @returns Promise that resolves to a boolean: true if the JWS is valid, or false otherwise
 */
export type JwsVerificationFunctionAsync<T extends string> = AsAsync<
  JwsVerificationFunctionSync<T>
>;

/**
 * Assert that the argument is a valid JWT header object.
 * Throws an error in case it is not.
 *
 * @param header
 * @returns void
 */
function assertJwtHeader(
  header: ReturnType<typeof safeJsonParse>
): asserts header is JwtHeader {
  if (!isJsonObject(header)) {
    throw new JwtParseError("JWT header is not an object");
  }
  if (header.alg !== undefined && typeof header.alg !== "string") {
    throw new JwtParseError("JWT header alg claim is not a string");
  }
  if (header.kid !== undefined && typeof header.kid !== "string") {
    throw new JwtParseError("JWT header kid claim is not a string");
  }
}

/**
 * Assert that the argument is a valid JWT payload object.
 * Throws an error in case it is not.
 *
 * @param payload
 * @returns void
 */
function assertJwtPayload(
  payload: ReturnType<typeof safeJsonParse>
): asserts payload is JwtPayload {
  if (!isJsonObject(payload)) {
    throw new JwtParseError("JWT payload is not an object");
  }
  if (payload.exp !== undefined && !Number.isFinite(payload.exp)) {
    throw new JwtParseError("JWT payload exp claim is not a number");
  }
  if (payload.iss !== undefined && typeof payload.iss !== "string") {
    throw new JwtParseError("JWT payload iss claim is not a string");
  }
  if (payload.sub !== undefined && typeof payload.sub !== "string") {
    throw new JwtParseError("JWT payload sub claim is not a string");
  }
  if (
    payload.aud !== undefined &&
    typeof payload.aud !== "string" &&
    (!Array.isArray(payload.aud) ||
      payload.aud.some((aud) => typeof aud !== "string"))
  ) {
    throw new JwtParseError(
      "JWT payload aud claim is not a string or array of strings"
    );
  }
  if (payload.nbf !== undefined && !Number.isFinite(payload.nbf)) {
    throw new JwtParseError("JWT payload nbf claim is not a number");
  }
  if (payload.iat !== undefined && !Number.isFinite(payload.iat)) {
    throw new JwtParseError("JWT payload iat claim is not a number");
  }
  if (payload.scope !== undefined && typeof payload.scope !== "string") {
    throw new JwtParseError("JWT payload scope claim is not a string");
  }
  if (payload.jti !== undefined && typeof payload.jti !== "string") {
    throw new JwtParseError("JWT payload jti claim is not a string");
  }
}

const JWT_REGEX =
  /^[A-Za-z0-9_-]+={0,2}\.[A-Za-z0-9_-]+={0,2}\.[A-Za-z0-9_-]+={0,2}$/;

/**
 * Sanity check, decompose and JSON parse a JWT string into its constituent, and yet unverified, parts:
 * - header object
 * - payload object
 * - signature string
 *
 * This function does NOT verify a JWT, do not trust the returned payload and header!
 *
 * For most use cases, you would not want to call this function directly yourself, rather you
 * would call verify() with the JWT, which would call this function (and others) for you.
 *
 * @param jwt The JWT (as string)
 * @returns the decomposed, and yet unverified, JWT
 */
export function decomposeUnverifiedJwt(jwt: unknown): DecomposedJwt {
  // Sanity checks on JWT
  if (!jwt) {
    throw new JwtParseError("Empty JWT");
  }
  if (typeof jwt !== "string") {
    throw new JwtParseError("JWT is not a string");
  }
  if (!JWT_REGEX.test(jwt)) {
    throw new JwtParseError(
      "JWT string does not consist of exactly 3 parts (header, payload, signature)"
    );
  }
  const [headerB64, payloadB64, signatureB64] = jwt.split(".");

  // B64 decode header and payload
  const [headerString, payloadString] = [headerB64, payloadB64].map(
    nodeWebCompat.parseB64UrlString
  );

  // Parse header
  let header: ReturnType<typeof safeJsonParse>;
  try {
    header = safeJsonParse(headerString);
  } catch (err) {
    throw new JwtParseError(
      "Invalid JWT. Header is not a valid JSON object",
      err
    );
  }
  assertJwtHeader(header);

  // parse payload
  let payload: ReturnType<typeof safeJsonParse>;
  try {
    payload = safeJsonParse(payloadString);
  } catch (err) {
    throw new JwtParseError(
      "Invalid JWT. Payload is not a valid JSON object",
      err
    );
  }
  assertJwtPayload(payload);

  return {
    header,
    headerB64,
    payload,
    payloadB64,
    signatureB64,
  };
}

export interface DecomposedJwt {
  /**
   * The yet unverified (!) header of the JWT
   */
  header: JwtHeader;
  /**
   * The yet unverified (!) header of the JWT, as base64url-encoded string
   */
  headerB64: string;
  /**
   * The yet unverified (!) payload of the JWT
   */
  payload: JwtPayload;
  /**
   * The yet unverified (!) payload of the JWT, as base64url-encoded string
   */
  payloadB64: string;
  /**
   * The yet unverified (!) signature of the JWT, as base64url-encoded string
   */
  signatureB64: string;
}

/**
 * Validate JWT payload fields. Throws an error in case there's any validation issue.
 *
 * @param payload The (JSON parsed) JWT payload
 * @param options The options to use during validation
 * @returns void
 */
export function validateJwtFields(
  payload: JwtPayload,
  options: {
    issuer?: string | string[] | null;
    audience?: string | string[] | null;
    scope?: string | string[] | null;
    graceSeconds?: number;
  }
): void {
  // Check expiry
  if (payload.exp !== undefined) {
    if (payload.exp + (options.graceSeconds ?? 0) < Date.now() / 1000) {
      throw new JwtExpiredError(
        `Token expired at ${new Date(payload.exp * 1000).toISOString()}`,
        payload.exp
      );
    }
  }

  // Check not before
  if (payload.nbf !== undefined) {
    if (payload.nbf - (options.graceSeconds ?? 0) > Date.now() / 1000) {
      throw new JwtNotBeforeError(
        `Token can't be used before ${new Date(
          payload.nbf * 1000
        ).toISOString()}`,
        payload.nbf
      );
    }
  }

  // Check JWT issuer
  if (options.issuer !== null) {
    if (options.issuer === undefined) {
      throw new ParameterValidationError(
        "issuer must be provided or set to null explicitly"
      );
    }
    assertStringArrayContainsString(
      "Issuer",
      payload.iss,
      options.issuer,
      JwtInvalidIssuerError
    );
  }

  // Check audience
  if (options.audience !== null) {
    if (options.audience === undefined) {
      throw new ParameterValidationError(
        "audience must be provided or set to null explicitly"
      );
    }
    assertStringArraysOverlap(
      "Audience",
      payload.aud,
      options.audience,
      JwtInvalidAudienceError
    );
  }

  // Check scope
  if (options.scope != null) {
    assertStringArraysOverlap(
      "Scope",
      payload.scope?.split(" "),
      options.scope,
      JwtInvalidScopeError
    );
  }
}
