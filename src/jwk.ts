// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { SimpleJsonFetcher, JsonFetcher, fetchJson } from "./https.js";
import { JwtHeader, JwtPayload } from "./jwt-model.js";
import { Json, JsonObject, isJsonObject } from "./safe-json-parse.js";
import {
  JwkValidationError,
  JwksNotAvailableInCacheError,
  JwksValidationError,
  KidNotFoundInJwksError,
  WaitPeriodNotYetEndedJwkError,
  JwtWithoutValidKidError,
} from "./error.js";

interface DecomposedJwt {
  header: JwtHeader;
  payload: JwtPayload;
}

const allJwkFields = ["alg", "e", "kid", "kty", "n", "use"] as const;

interface JwkFields {
  alg: "RS256" | string;
  kid: string;
  kty: string;
  use: string;
  n: string;
  e: string;
  [key: string]: unknown;
}

export type Jwk = JwkFields & JsonObject;

interface JwksFields {
  keys: readonly Jwk[];
}

export type Jwks = JwksFields & JsonObject;

export interface JwksCache {
  getJwk(jwksUri: string, decomposedJwt: DecomposedJwt): Promise<Jwk>;
  getCachedJwk(jwksUri: string, decomposedJwt: DecomposedJwt): Jwk;
  addJwks(jwksUri: string, jwks: Jwks): void;
  getJwks(jwksUri: string): Promise<Jwks>;
}

export async function fetchJwks(jwksUri: string): Promise<Jwks> {
  const jwks = await fetchJson(jwksUri);
  assertIsJwks(jwks);
  return jwks;
}

export async function fetchJwk(
  jwksUri: string,
  decomposedJwt: DecomposedJwt
): Promise<Jwk> {
  if (!decomposedJwt.header.kid) {
    throw new JwtWithoutValidKidError(
      "JWT header does not have valid kid claim"
    );
  }
  const jwk = (await fetchJwks(jwksUri)).keys.find(
    (key) => key.kid === decomposedJwt.header.kid
  );
  if (!jwk) {
    throw new KidNotFoundInJwksError(
      `JWK for kid "${decomposedJwt.header.kid}" not found in the JWKS`
    );
  }
  return jwk;
}

export function assertIsJwks(jwks: Json): asserts jwks is Jwks {
  if (!jwks) {
    throw new JwksValidationError("JWKS empty");
  }
  if (!isJsonObject(jwks)) {
    throw new JwksValidationError("JWKS should be an object");
  }
  if (!Object.keys(jwks).includes("keys")) {
    throw new JwksValidationError("JWKS does not include keys");
  }
  if (!Array.isArray((jwks as { keys: Json }).keys)) {
    throw new JwksValidationError("JWKS keys should be an array");
  }
  for (const jwk of (jwks as { keys: Json[] }).keys) {
    assertIsJwk(jwk);
  }
}

export function assertIsJwk(jwk: Json): asserts jwk is Jwk {
  if (!jwk) {
    throw new JwkValidationError("JWK empty");
  }
  if (!isJsonObject(jwk)) {
    throw new JwkValidationError("JWK should be an object");
  }
  for (const field of allJwkFields) {
    if (!(field in jwk)) {
      throw new JwkValidationError(`JWK ${field} should be a string`);
    }
  }
}

export function isJwks(jwks: Json): jwks is Jwks {
  try {
    assertIsJwks(jwks);
    return true;
  } catch {
    return false;
  }
}

export function isJwk(jwk: Json): jwk is Jwk {
  try {
    assertIsJwk(jwk);
    return true;
  } catch {
    return false;
  }
}

export interface PenaltyBox {
  wait: (jwksUri: string, kid: string) => Promise<void>;
  release: (jwksUri: string, kid?: string) => void;
  registerFailedAttempt: (jwksUri: string, kid: string) => void;
  registerSuccessfulAttempt: (jwksUri: string, kid: string) => void;
}

type JwksUri = string;

export class SimplePenaltyBox implements PenaltyBox {
  waitSeconds: number;
  private waitingUris: Map<JwksUri, NodeJS.Timeout> = new Map();
  constructor(props?: { waitSeconds?: number }) {
    this.waitSeconds = props?.waitSeconds ?? 10;
  }
  async wait(jwksUri: string): Promise<void> {
    // SimplePenaltyBox does not actually wait but bluntly throws an error
    // Any waiting and retries are expected to be done upstream (e.g. in the browser / app)
    if (this.waitingUris.has(jwksUri)) {
      throw new WaitPeriodNotYetEndedJwkError(
        "Not allowed to fetch JWKS yet, still waiting for back off period to end"
      );
    }
  }
  release(jwksUri: string): void {
    const i = this.waitingUris.get(jwksUri);
    if (i) {
      clearTimeout(i);
      this.waitingUris.delete(jwksUri);
    }
  }
  registerFailedAttempt(jwksUri: string): void {
    const i = setTimeout(() => {
      this.waitingUris.delete(jwksUri);
    }, this.waitSeconds * 1000).unref();
    this.waitingUris.set(jwksUri, i);
  }
  registerSuccessfulAttempt(jwksUri: string): void {
    this.release(jwksUri);
  }
}

export class SimpleJwksCache implements JwksCache {
  fetcher: JsonFetcher;
  penaltyBox: PenaltyBox;
  private jwksCache: Map<JwksUri, Jwks> = new Map();
  private fetchingJwks: Map<JwksUri, Promise<Jwks>> = new Map();

  constructor(props?: { penaltyBox?: PenaltyBox; fetcher?: JsonFetcher }) {
    this.penaltyBox = props?.penaltyBox ?? new SimplePenaltyBox();
    this.fetcher = props?.fetcher ?? new SimpleJsonFetcher();
  }

  public addJwks(jwksUri: string, jwks: Jwks): void {
    this.jwksCache.set(jwksUri, jwks);
  }

  public async getJwks(jwksUri: string): Promise<Jwks> {
    const existingFetch = this.fetchingJwks.get(jwksUri);
    if (existingFetch) {
      return existingFetch;
    }
    const jwksPromise = this.fetcher.fetch(jwksUri).then((res) => {
      assertIsJwks(res);
      return res;
    });
    this.fetchingJwks.set(jwksUri, jwksPromise);
    let jwks: Jwks;
    try {
      jwks = await jwksPromise;
    } finally {
      this.fetchingJwks.delete(jwksUri);
    }
    this.jwksCache.set(jwksUri, jwks);
    return jwks;
  }

  public getCachedJwk(jwksUri: string, decomposedJwt: DecomposedJwt): Jwk {
    if (typeof decomposedJwt.header.kid !== "string") {
      throw new JwtWithoutValidKidError(
        "JWT header does not have valid kid claim"
      );
    }
    if (!this.jwksCache.has(jwksUri)) {
      throw new JwksNotAvailableInCacheError(
        `JWKS for uri ${jwksUri} not yet available in cache`
      );
    }
    const jwk = this.jwksCache
      .get(jwksUri)!
      .keys.find((key) => key.kid === decomposedJwt.header.kid);
    if (!jwk) {
      throw new KidNotFoundInJwksError(
        `JWK for kid ${decomposedJwt.header.kid} not found in the JWKS`
      );
    }
    return jwk;
  }

  public async getJwk(
    jwksUri: string,
    decomposedJwt: DecomposedJwt
  ): Promise<Jwk> {
    if (typeof decomposedJwt.header.kid !== "string") {
      throw new JwtWithoutValidKidError(
        "JWT header does not have valid kid claim"
      );
    }

    // Try to get JWK from cache:
    let jwk = this.jwksCache
      .get(jwksUri)
      ?.keys.find((key) => key.kid === decomposedJwt.header.kid);
    if (jwk) {
      return jwk;
    }

    // Await any wait period that is currently in effect
    // This prevents us from flooding the JWKS URI with requests
    await this.penaltyBox.wait(jwksUri, decomposedJwt.header.kid);

    // Fetch the JWKS and (try to) locate the JWK
    const jwks = await this.getJwks(jwksUri);
    jwk = jwks.keys.find((key) => key.kid === decomposedJwt.header.kid);

    // If the JWK could not be located, someone might be messing around with us
    // Register the failed attempt with the penaltyBox, so it can enforce a wait period
    // before trying again next time (instead of flooding the JWKS URI with requests)
    if (!jwk) {
      this.penaltyBox.registerFailedAttempt(jwksUri, decomposedJwt.header.kid);
      throw new KidNotFoundInJwksError(
        `JWK for kid "${decomposedJwt.header.kid}" not found in the JWKS`
      );
    } else {
      this.penaltyBox.registerSuccessfulAttempt(
        jwksUri,
        decomposedJwt.header.kid
      );
    }

    return jwk;
  }
}
