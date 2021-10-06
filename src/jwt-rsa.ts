// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { createVerify, createPublicKey, KeyObject } from "crypto";
import { URL } from "url";
import { join } from "path";
import {
  SimpleJwksCache,
  JwksCache,
  Jwk,
  Jwks,
  isJwk,
  isJwks,
  fetchJwk,
} from "./jwk.js";
import { constructPublicKeyInDerFormat } from "./asn1.js";
import {
  assertStringArrayContainsString,
  assertStringEquals,
} from "./assert.js";
import { JwtHeader, JwtPayload } from "./jwt-model.js";
import {
  StillToProvideVerifyProps,
  WithoutOptionalFields,
} from "./typing-util.js";
import { decomposeJwt, validateJwtFields } from "./jwt.js";
import {
  JwtInvalidSignatureError,
  JwtInvalidClaimError,
  ParameterValidationError,
  KidNotFoundInJwksError,
} from "./error.js";
import { JsonObject } from "./safe-json-parse.js";

/** Interface for JWT verification properties */
interface VerifyProperties {
  /**
   * The audience that you expect to be present in the JWT's aud claim.
   * If you provide a string array, that means at least one of those audiences
   * must be present in the JWT's aud claim.
   * Pass null explicitly to not check the JWT's audience--if you know what you're doing
   */
  audience: string | string[] | null;
  /**
   * The scope that you expect to be present in the JWT's scope claim.
   * If you provide a string array, that means at least one of those scopes
   * must be present in the JWT's scope claim.
   */
  scope?: string | string[];
  /**
   * The number of seconds after expiration (exp claim) or before not-before (nbf claim) that you will allow
   * (use this to account for clock differences between systems)
   */
  graceSeconds?: number;
  /**
   * Your custom function with checks. It will be called, at the end of the verification,
   * after standard verifcation checks have all passed.
   * Throw an error in this function if you want to reject the JWT for whatever reason you deem fit.
   * Your function will be called with a properties object that contains:
   * - the decoded JWT header
   * - the decoded JWT payload
   * - the JWK that was used to verify the JWT's signature
   */
  customJwtCheck?: (props: {
    header: JwtHeader;
    payload: JwtPayload;
    jwk: Jwk;
  }) => Promise<void> | void;
}

/** Interface for JWT RSA verifier properties, for a single issuer */
export interface JwtRsaVerifierProperties extends Partial<VerifyProperties> {
  /**
   * URI where the JWKS (JSON Web Key Set) can be downloaded from.
   * The JWKS contains one or more JWKs, which represent the public keys with which
   * JWTs have been signed.
   */
  jwksUri?: string;
  /**
   * The issuer of the JWTs you want to verify.
   * Set this to the expected value of the `iss` claim in the JWT.
   */
  issuer: string;
}

/**
 * Interface for JWT RSA verifier properties, when multiple issuers are used in the verifier.
 * In this case, you should be explicit in mapping audience to issuer.
 */
interface JwtRsaVerifierMultiProperties extends VerifyProperties {
  /**
   * URI where the JWKS (JSON Web Key Set) can be downloaded from.
   * The JWKS contains one or more JWKs, which represent the public keys with which
   * JWTs have been signed.
   */
  jwksUri?: string;
  /**
   * The issuer of the JWTs you want to verify.
   * Set this to the expected value of the `iss` claim in the JWT.
   */
  issuer: string;
}

/**
 * Verify a JWTs signature agains a JWK. This function throws an error if the JWT is not valid
 *
 * @param header The decoded and JSON parsed JWT header
 * @param headerB64 The JWT header in base64 encoded form
 * @param payload The decoded and JSON parsed JWT payload
 * @param payloadB64 The JWT payload in base64 encoded form
 * @param signatureB64 The JWT signature in base64 encoded form
 * @param jwk The JWK with which the JWT was signed
 * @param jwkToKeyObjectTransformer Function to transform the JWK into a NodeJS native key object
 * @returns void
 */
function verifySignatureAgainstJwk(
  header: JwtHeader,
  headerB64: string,
  payload: JwtPayload,
  payloadB64: string,
  signatureB64: string,
  jwk: Jwk,
  jwkToKeyObjectTransformer: JwkToKeyObjectTransformer = transformJwkToKeyObject
) {
  // Check JWK use
  assertStringEquals("JWK use", jwk.use, "sig");

  // Check that JWT signature algorithm matches JWK
  assertStringEquals("JWT signature algorithm", header.alg, jwk.alg);

  // Check JWT signature algorithm is RS256
  assertStringEquals("JWT signature algorithm", header.alg, "RS256");

  // Convert JWK modulus and exponent into DER public key
  const publicKey = jwkToKeyObjectTransformer(jwk, payload.iss, header.kid);

  // Verify the JWT signature
  // RS256 is known in OpenSSL as RSA-SHA256
  const valid = createVerify("RSA-SHA256")
    .update(`${headerB64}.${payloadB64}`)
    .verify(publicKey, signatureB64, "base64");
  if (!valid) {
    throw new JwtInvalidSignatureError("Invalid signature");
  }
}

/**
 * Verify a JWT asynchronously (thus allowing for the JWKS to be fetched from the JWKS URI)
 *
 * @param jwt The JWT
 * @param jwksUri The JWKS URI, where the JWKS can be fetched from
 * @param options Verification options
 * @param jwkFetcher A function that can execute the fetch of the JWKS from the JWKS URI
 * @param jwkToKeyObjectTransformer A function that can transform a JWK into a NodeJS native key object
 * @returns Promise that resolves to the payload of the JWT––if the JWT is valid, otherwise the promise rejects
 */
export async function verifyJwt(
  jwt: string,
  jwksUri: string,
  options: {
    issuer: string | string[] | null;
    audience: string | string[] | null;
    scope?: string | string[];
    graceSeconds?: number;
    customJwtCheck?: (props: {
      header: JwtHeader;
      payload: JwtPayload;
      jwk: Jwk;
    }) => Promise<void> | void;
  },
  jwkFetcher?: (
    jwksUri: string,
    decomposedJwt: ReturnType<typeof decomposeJwt>
  ) => Promise<Jwk>,
  jwkToKeyObjectTransformer?: JwkToKeyObjectTransformer
): Promise<JwtPayload> {
  return verifyDecomposedJwt(
    decomposeJwt(jwt),
    jwksUri,
    options,
    jwkFetcher,
    jwkToKeyObjectTransformer
  );
}

/**
 * Verify (asynchronously) a JWT that is already decomposed (by function `decomposeJwt`)
 *
 * @param decomposedJwt The decomposed JWT
 * @param jwksUri The JWKS URI, where the JWKS can be fetched from
 * @param options Verification options
 * @param jwkFetcher A function that can execute the fetch of the JWKS from the JWKS URI
 * @param jwkToKeyObjectTransformer A function that can transform a JWK into a NodeJS native key object
 * @returns Promise that resolves to the payload of the JWT––if the JWT is valid, otherwise the promise rejects
 */
async function verifyDecomposedJwt(
  decomposedJwt: ReturnType<typeof decomposeJwt>,
  jwksUri: string,
  options: {
    issuer?: string | string[] | null;
    audience?: string | string[] | null;
    scope?: string | string[] | null;
    graceSeconds?: number;
    customJwtCheck?: (props: {
      header: JwtHeader;
      payload: JwtPayload;
      jwk: Jwk;
    }) => Promise<void> | void;
  },
  jwkFetcher: (
    jwksUri: string,
    decomposedJwt: ReturnType<typeof decomposeJwt>
  ) => Promise<Jwk> = fetchJwk,
  jwkToKeyObjectTransformer?: JwkToKeyObjectTransformer
) {
  const { header, headerB64, payload, payloadB64, signatureB64 } =
    decomposedJwt;

  validateJwtFields(payload, options);

  const jwk = await jwkFetcher(jwksUri, decomposedJwt);

  verifySignatureAgainstJwk(
    header,
    headerB64,
    payload,
    payloadB64,
    signatureB64,
    jwk,
    jwkToKeyObjectTransformer
  );

  if (options.customJwtCheck) {
    await options.customJwtCheck({ header, payload, jwk });
  }

  return payload;
}

/**
 * Verify a JWT synchronously, using a JWKS or JWK that has already been fetched
 *
 * @param jwt The JWT
 * @param jwkOrJwks The JWKS that includes the right JWK (indexed by kid). Alternatively, provide the right JWK directly
 * @param options Verification options
 * @param jwkToKeyObjectTransformer A function that can transform a JWK into a NodeJS native key object
 * @returns The (JSON parsed) payload of the JWT––if the JWT is valid, otherwise an error is thrown
 */
export function verifyJwtSync(
  jwt: string,
  jwkOrJwks: Jwk | Jwks,
  options: {
    issuer: string | string[] | null;
    audience: string | string[] | null;
    scope?: string | string[];
    graceSeconds?: number;
    customJwtCheck?: (props: {
      header: JwtHeader;
      payload: JwtPayload;
      jwk: Jwk;
    }) => void;
  },
  jwkToKeyObjectTransformer?: JwkToKeyObjectTransformer
): JwtPayload {
  return verifyDecomposedJwtSync(
    decomposeJwt(jwt),
    jwkOrJwks,
    options,
    jwkToKeyObjectTransformer
  );
}

/**
 * Verify (synchronously) a JWT that is already decomposed (by function `decomposeJwt`)
 *
 * @param decomposedJwt The decomposed JWT
 * @param jwkOrJwks The JWKS that includes the right JWK (indexed by kid). Alternatively, provide the right JWK directly
 * @param options Verification options
 * @param jwkToKeyObjectTransformer A function that can transform a JWK into a NodeJS native key object
 * @returns The (JSON parsed) payload of the JWT––if the JWT is valid, otherwise an error is thrown
 */
function verifyDecomposedJwtSync(
  decomposedJwt: ReturnType<typeof decomposeJwt>,
  jwkOrJwks: JsonObject,
  options: {
    issuer?: string | string[] | null;
    audience?: string | string[] | null;
    scope?: string | string[] | null;
    graceSeconds?: number;
    customJwtCheck?: (props: {
      header: JwtHeader;
      payload: JwtPayload;
      jwk: Jwk;
    }) => void;
  },
  jwkToKeyObjectTransformer?: JwkToKeyObjectTransformer
) {
  const { header, headerB64, payload, payloadB64, signatureB64 } =
    decomposedJwt;

  validateJwtFields(payload, options);

  let jwk: Jwk;
  if (isJwk(jwkOrJwks)) {
    jwk = jwkOrJwks;
  } else if (isJwks(jwkOrJwks)) {
    const locatedJwk = jwkOrJwks.keys.find((key) => key.kid === header.kid);
    if (!locatedJwk) {
      throw new KidNotFoundInJwksError(
        `JWK for kid ${header.kid} not found in the JWKS`
      );
    }
    jwk = locatedJwk;
  } else {
    throw new ParameterValidationError(
      [
        `Expected a valid JWK or JWKS (parsed as JavaScript object), but received: ${jwkOrJwks}.`,
        "If you're passing a JWKS URI, use the async verify() method instead, it will download and parse the JWKS for you",
      ].join()
    );
  }

  verifySignatureAgainstJwk(
    header,
    headerB64,
    payload,
    payloadB64,
    signatureB64,
    jwk,
    jwkToKeyObjectTransformer
  );

  if (options.customJwtCheck) {
    const res = options.customJwtCheck({ header, payload, jwk });
    if (res !== undefined && (res as unknown) instanceof Promise) {
      throw new ParameterValidationError(
        "Custom JWT checks must be synchronous but a promise was returned"
      );
    }
  }

  return payload;
}

/** Type alias for better readability below */
type Issuer = string;
type Kid = string;

/**
 * Abstract class representing a verifier for JWTs signed with RSA (e.g. RS256)
 *
 * A class is used, because there is state:
 * - The JWKS is fetched (downloaded) from the JWKS URI and cached in memory
 * - Verification properties at verifier level, are used as default options for individual verify calls
 *
 * When instantiating this class, relevant type parameters should be provided, for your concrete case:
 * @param StillToProvide The verification options that you want callers of verify to provide on individual verify calls
 * @param SpecificVerifyProperties The verification options that you'll use
 * @param IssuerConfig The issuer config that you'll use (config options are used as default verification options)
 * @param MultiIssuer Verify multiple issuers (true) or just a single one (false)
 */
export abstract class JwtRsaVerifierBase<
  StillToProvide extends Partial<SpecificVerifyProperties>,
  SpecificVerifyProperties,
  IssuerConfig extends {
    issuer: string;
    jwksUri?: string;
  } & Partial<SpecificVerifyProperties>,
  MultiIssuer extends boolean
> {
  private issuersConfig: Map<Issuer, IssuerConfig & { jwksUri: string }> =
    new Map();
  private publicKeyCache = new KeyObjectCache();
  protected constructor(
    verifyProperties: IssuerConfig | IssuerConfig[],
    private jwksCache: JwksCache = new SimpleJwksCache()
  ) {
    if (Array.isArray(verifyProperties)) {
      if (!verifyProperties.length) {
        throw new ParameterValidationError(
          "Provide at least one issuer configuration"
        );
      }
      for (const prop of verifyProperties) {
        if (this.issuersConfig.has(prop.issuer)) {
          throw new ParameterValidationError(
            `issuer ${prop.issuer} supplied multiple times`
          );
        }
        this.issuersConfig.set(prop.issuer, this.withJwksUri(prop));
      }
    } else {
      this.issuersConfig.set(
        verifyProperties.issuer,
        this.withJwksUri(verifyProperties)
      );
    }
  }

  protected get expectedIssuers(): string[] {
    return Array.from(this.issuersConfig.keys());
  }

  protected getIssuerConfig(
    issuer?: string
  ): IssuerConfig & { jwksUri: string } {
    if (!issuer) {
      if (this.issuersConfig.size !== 1) {
        throw new ParameterValidationError("issuer must be provided");
      }
      issuer = this.issuersConfig.keys().next().value;
    }
    const config = this.issuersConfig.get(issuer!);
    if (!config) {
      throw new ParameterValidationError(`issuer not configured: ${issuer}`);
    }
    return config;
  }

  /**
   * This method loads a JWKS that you provide, into the JWKS cache, so that it is
   * available for JWT verification. Use this method to speed up the first JWT verification
   * (when the JWKS would otherwise have to be downloaded from the JWKS uri), or to provide the JWKS
   * in case the JwtVerifier does not have internet access to download the JWKS
   *
   * @param jwksThe JWKS
   * @param issuer The issuer for which you want to cache the JWKS
   *  Supply this field, if you instantiated the JwtVerifier with multiple issuers
   * @returns void
   */
  public cacheJwks(
    ...args: MultiIssuer extends false
      ? [jwks: Jwks, issuer?: string]
      : [jwks: Jwks, issuer: string]
  ): void {
    const issuerConfig = this.getIssuerConfig(args[1]);
    this.jwksCache.addJwks(issuerConfig.jwksUri, args[0]);
    this.publicKeyCache.clearCache(issuerConfig.issuer);
  }

  /**
   * Hydrate the JWKS cache for (all of) the configured issuer(s).
   * This will fetch and cache the latest and greatest JWKS for concerned issuer(s).
   *
   * @param issuer The issuer to fetch the JWKS for
   * @returns void
   */
  async hydrate(): Promise<void> {
    const jwksFetches = this.expectedIssuers
      .map((issuer) => this.getIssuerConfig(issuer).jwksUri)
      .map((jwksUri) => this.jwksCache.getJwks(jwksUri));
    await Promise.all(jwksFetches);
  }

  /**
   * Verify (synchronously) a JWT that is signed using RS256.
   *
   * @param jwt The JWT, as string
   * @param props Verification properties
   * @returns The payload of the JWT––if the JWT is valid, otherwise an error is thrown
   */
  public verifySync(
    ...args: { [key: string]: never } extends StillToProvide
      ? [jwt: string, props?: Partial<SpecificVerifyProperties>]
      : [jwt: string, props: StillToProvide]
  ): JwtPayload {
    const { decomposedJwt, jwksUri, verifyProperties } =
      this.getVerifyParameters(args[0], args[1]);
    const jwk = this.jwksCache.getCachedJwk(jwksUri, decomposedJwt);
    return verifyDecomposedJwtSync(
      decomposedJwt,
      jwk,
      verifyProperties,
      this.publicKeyCache.transformJwkToKeyObject.bind(this.publicKeyCache)
    );
  }
  /**
   * Verify (asynchronously) a JWT that is signed using RS256.
   * This call is asynchronous, and the JWKS will be fetched from the JWKS uri,
   * in case it is not yet available in the cache.
   *
   * @param jwt The JWT, as string
   * @param props Verification properties
   * @returns Promise that resolves to the payload of the JWT––if the JWT is valid, otherwise the promise rejects
   */
  public async verify(
    ...args: { [key: string]: never } extends StillToProvide
      ? [jwt: string, props?: Partial<SpecificVerifyProperties>]
      : [jwt: string, props: StillToProvide]
  ): Promise<JwtPayload> {
    const { decomposedJwt, jwksUri, verifyProperties } =
      this.getVerifyParameters(args[0], args[1]);
    return verifyDecomposedJwt(
      decomposedJwt,
      jwksUri,
      verifyProperties,
      this.jwksCache.getJwk.bind(this.jwksCache),
      this.publicKeyCache.transformJwkToKeyObject.bind(this.publicKeyCache)
    );
  }

  /**
   * Get the verification parameters to use, by merging the issuer configuration,
   * with the overriding properties that are now provided
   *
   * @param jwt: the JWT that is going to be verified
   * @param verifyProperties: the overriding properties, that override the issuer configuration
   * @returns The merged verification parameters
   */
  private getVerifyParameters(
    jwt: string,
    verifyProperties?: Partial<SpecificVerifyProperties>
  ): {
    decomposedJwt: ReturnType<typeof decomposeJwt>;
    jwksUri: string;
    verifyProperties: SpecificVerifyProperties;
  } {
    const decomposedJwt = decomposeJwt(jwt);
    if (!decomposedJwt.payload.iss) {
      throw new JwtInvalidClaimError("JWT payload does not have iss claim");
    }
    assertStringArrayContainsString(
      "Issuer",
      decomposedJwt.payload.iss,
      this.expectedIssuers
    );
    const issuerConfig = this.getIssuerConfig(decomposedJwt.payload.iss);
    return {
      decomposedJwt,
      jwksUri: issuerConfig.jwksUri,
      verifyProperties: {
        ...issuerConfig,
        ...verifyProperties,
      } as unknown as SpecificVerifyProperties,
    };
  }

  /**
   * Get issuer config with JWKS URI, by adding a default JWKS URI if needed
   *
   * @param config: the issuer config.
   * @returns The config with JWKS URI
   */
  private withJwksUri(
    config: IssuerConfig
  ): IssuerConfig & { jwksUri: string } {
    if (config.jwksUri) {
      return config as IssuerConfig & { jwksUri: string };
    }
    const issuerUri = new URL(config.issuer);
    return {
      jwksUri: new URL(
        join(issuerUri.pathname, "/.well-known/jwks.json"),
        config.issuer
      ).href,
      ...config,
    };
  }
}

/**
 * Class representing a verifier for JWTs signed with RSA (e.g. RS256)
 */
export class JwtRsaVerifier<
  StillToProvide extends Partial<VerifyProperties>,
  IssuerConfig extends JwtRsaVerifierProperties,
  MultiIssuer extends boolean
> extends JwtRsaVerifierBase<
  StillToProvide,
  VerifyProperties,
  IssuerConfig,
  MultiIssuer
> {
  /**
   * Create an RSA JWT verifier for a single issuer
   *
   * @param verifyProperties The verification properties for your issuer
   * @param additionalProperties Additional properties
   * @param additionalProperties.jwksCache Overriding JWKS cache that you want to use
   * @returns An RSA JWT Verifier instance, that you can use to verify JWTs with
   */
  static create<T extends JwtRsaVerifierProperties>(
    verifyProperties: T,
    additionalProperties?: { jwksCache: JwksCache }
  ): JwtRsaVerifierBase<
    StillToProvideVerifyProps<
      WithoutOptionalFields<VerifyProperties>,
      typeof verifyProperties
    > &
      Partial<VerifyProperties>,
    VerifyProperties,
    JwtRsaVerifierProperties,
    false
  >;
  /**
   * Create an RSA JWT verifier for multiple issuer
   *
   * @param verifyProperties An array of verification properties, one for each issuer
   * @param additionalProperties Additional properties
   * @param additionalProperties.jwksCache Overriding JWKS cache that you want to use
   * @returns An RSA JWT Verifier instance, that you can use to verify JWTs with
   */
  static create<T extends JwtRsaVerifierMultiProperties>(
    verifyProperties: T[],
    additionalProperties?: { jwksCache: JwksCache }
  ): JwtRsaVerifierBase<
    Partial<VerifyProperties>,
    VerifyProperties,
    JwtRsaVerifierMultiProperties,
    true
  >;
  // eslint-disable-next-line @typescript-eslint/explicit-module-boundary-types
  static create(
    verifyProperties:
      | JwtRsaVerifierProperties
      | JwtRsaVerifierMultiProperties[],
    additionalProperties?: { jwksCache: JwksCache }
  ) {
    return new this(verifyProperties, additionalProperties?.jwksCache);
  }
}

/** Interface for functions that can transform a JWK into an RSA public key in NodeJS native key object format */
export type JwkToKeyObjectTransformer = (
  jwk: Jwk,
  issuer?: string,
  kid?: string
) => KeyObject;

/**
 * Transform the JWK into an RSA public key in NodeJS native key object format
 *
 * @param jwk: the JWK
 * @returns the RSA public key in NodeJS native key object format
 */
export const transformJwkToKeyObject: JwkToKeyObjectTransformer = (jwk: Jwk) =>
  createPublicKey({
    key: constructPublicKeyInDerFormat(
      Buffer.from(jwk.n, "base64"),
      Buffer.from(jwk.e, "base64")
    ),
    format: "der",
    type: "spki",
  });

/**
 * Class representing a cache of RSA public keys in NodeJS native key object format
 *
 * Because it takes a bit of compute time to turn a JWK into NodeJS native key object format,
 * we want to cache this computation.
 */
export class KeyObjectCache {
  private publicKeys: Map<Issuer, Map<Kid, KeyObject>> = new Map();

  constructor(
    public jwkToKeyObjectTransformer: JwkToKeyObjectTransformer = transformJwkToKeyObject
  ) {}

  /**
   * Transform the JWK into an RSA public key in NodeJS native key object format.
   * If the transformed JWK is already in the cache, it is returned from the cache instead.
   * The cache keys are: issuer, JWK kid (key id)
   *
   * @param jwk: the JWK
   * @param issuer: the issuer that uses the JWK for signing JWTs
   * @returns the RSA public key in NodeJS native key object format
   */
  transformJwkToKeyObject(jwk: Jwk, issuer?: Issuer): KeyObject {
    if (!issuer) {
      return this.jwkToKeyObjectTransformer(jwk);
    }
    const cachedPublicKey = this.publicKeys.get(issuer)?.get(jwk.kid);
    if (cachedPublicKey) {
      return cachedPublicKey;
    }
    const publicKey = this.jwkToKeyObjectTransformer(jwk);
    const cachedIssuer = this.publicKeys.get(issuer);
    if (cachedIssuer) {
      cachedIssuer.set(jwk.kid, publicKey);
    } else {
      this.publicKeys.set(issuer, new Map([[jwk.kid, publicKey]]));
    }
    return publicKey;
  }

  clearCache(issuer: Issuer): void {
    this.publicKeys.delete(issuer);
  }
}
