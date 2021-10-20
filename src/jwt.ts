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
  JwtParseError,
  ParameterValidationError,
} from "./error.js";

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

/**
 * Sanity check, decompose and JSON parse a JWT string into its constituent parts:
 * - header object
 * - payload object
 * - signature string
 *
 * @param jwt The JWT (as string)
 * @returns the decomposed JWT
 */
export function decomposeJwt(jwt: unknown): {
  header: JwtHeader;
  headerB64: string;
  payload: JwtPayload;
  payloadB64: string;
  signatureB64: string;
} {
  // Sanity checks on JWT
  if (!jwt) {
    throw new JwtParseError("Empty JWT");
  }
  if (typeof jwt !== "string") {
    throw new JwtParseError("JWT is not a string");
  }
  if (!jwt.match(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/)) {
    throw new JwtParseError(
      "JWT string does not consist of exactly 3 parts (header, payload, signature)"
    );
  }
  const [headerB64, payloadB64, signatureB64] = jwt.split(".");

  // B64 decode header and payload
  const [headerString, payloadString] = [headerB64, payloadB64].map((b64) =>
    Buffer.from(b64, "base64").toString("utf8")
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
        `Token expired at ${new Date(payload.exp * 1000).toISOString()}`
      );
    }
  }

  // Check not before
  if (payload.nbf !== undefined) {
    if (payload.nbf - (options.graceSeconds ?? 0) > Date.now() / 1000) {
      throw new JwtNotBeforeError(
        `Token can't be used before ${new Date(
          payload.nbf * 1000
        ).toISOString()}`
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
    assertStringArrayContainsString("Issuer", payload.iss, options.issuer);
  }

  // Check audience
  if (options.audience !== null) {
    if (options.audience === undefined) {
      throw new ParameterValidationError(
        "audience must be provided or set to null explicitly"
      );
    }
    assertStringArraysOverlap("Audience", payload.aud, options.audience);
  }

  // Check scope
  if (options.scope != null) {
    assertStringArraysOverlap(
      "Scope",
      payload.scope?.split(" "),
      options.scope
    );
  }
}
