// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  CognitoJwtInvalidClientIdError,
  CognitoJwtInvalidGroupError,
  CognitoJwtInvalidTokenUseError,
  JwtInvalidClaimError,
  ParameterValidationError,
} from "./error.js";
import { JwtVerifierBase, JwtVerifierProperties } from "./jwt-verifier.js";
import { JwksCache, Jwks, Jwk } from "./jwk.js";
import {
  JwtHeader,
  JwtPayload,
  CognitoIdOrAccessTokenPayload,
} from "./jwt-model.js";
import {
  assertStringArrayContainsString,
  assertStringEquals,
  assertStringArraysOverlap,
} from "./assert.js";
import { Properties } from "./typing-util.js";

export interface CognitoVerifyProperties {
  /**
   * The client ID that you expect to be present on the JWT
   * (In the ID token's aud claim, or the Access token's client_id claim).
   * If you provide a string array, that means at least one of those client IDs
   * must be present on the JWT.
   * Pass null explicitly to not check the JWT's client ID--if you know what you're doing
   */
  clientId: string | string[] | null;
  /**
   * The token use that you expect to be present in the JWT's token_use claim.
   * Usually you are verifying either Access token (common) or ID token (less common).
   * Pass null explicitly to not check the JWT's token use--if you know what you're doing
   */
  tokenUse: "id" | "access" | null;
  /**
   * The group that you expect to be present in the JWT's "cognito:groups" claim.
   * If you provide a string array, that means at least one of those groups
   * must be present in the JWT's "cognito:groups" claim.
   */
  groups?: string | string[] | null;
  /**
   * The scope that you expect to be present in the JWT's scope claim.
   * If you provide a string array, that means at least one of those scopes
   * must be present in the JWT's scope claim.
   */
  scope?: string | string[] | null;
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
  /**
   * If you want to peek inside the invalid JWT when verification fails, set `includeRawJwtInErrors` to true.
   * Then, if an error is thrown during verification of the invalid JWT (e.g. the JWT is invalid because it is expired),
   * the Error object will include a property `rawJwt`, with the raw decoded contents of the **invalid** JWT.
   * The `rawJwt` will only be included in the Error object, if the JWT's signature can at least be verified.
   */
  includeRawJwtInErrors?: boolean;
}

/** Type for Cognito JWT verifier properties, for a single User Pool */
export type CognitoJwtVerifierProperties = {
  /** The User Pool whose JWTs you want to verify */
  userPoolId: string;
} & Partial<CognitoVerifyProperties>;

/**
 * Type for Cognito JWT verifier properties, when multiple User Pools are used in the verifier.
 * In this case, you should be explicit in mapping `clientId` to User Pool.
 */
export type CognitoJwtVerifierMultiProperties = {
  /** The User Pool whose JWTs you want to verify */
  userPoolId: string;
} & CognitoVerifyProperties;

/**
 * Cognito JWT Verifier for a single user pool
 */
export type CognitoJwtVerifierSingleUserPool<
  T extends CognitoJwtVerifierProperties,
> = CognitoJwtVerifier<
  Properties<CognitoVerifyProperties, T>,
  T &
    JwtVerifierProperties<CognitoVerifyProperties> & {
      userPoolId: string;
      audience: null;
    },
  false
>;

/**
 * Cognito JWT Verifier for multiple user pools
 */
export type CognitoJwtVerifierMultiUserPool<
  T extends CognitoJwtVerifierMultiProperties,
> = CognitoJwtVerifier<
  Properties<CognitoVerifyProperties, T>,
  T &
    JwtVerifierProperties<CognitoVerifyProperties> & {
      userPoolId: string;
      audience: null;
    },
  true
>;

/**
 * Parameters used for verification of a JWT.
 * The first parameter is the JWT, which is (of course) mandatory.
 * The second parameter is an object with specific properties to use during verification.
 * The second parameter is only mandatory if its mandatory members (e.g. client_id) were not
 *  yet provided at verifier level. In that case, they must now be provided.
 */
type CognitoVerifyParameters<SpecificVerifyProperties> = {
  [key: string]: never;
} extends SpecificVerifyProperties
  ? [jwt: string, props?: SpecificVerifyProperties]
  : [jwt: string, props: SpecificVerifyProperties];

/**
 * Validate claims of a decoded Cognito JWT.
 * This function throws an error in case there's any validation issue.
 *
 * @param payload - The JSON parsed payload of the Cognito JWT
 * @param options - Validation options
 * @param options.groups - The cognito groups, of which at least one must be present in the JWT's cognito:groups claim
 * @param options.tokenUse - The required token use of the JWT: "id" or "access"
 * @param options.clientId - The required clientId of the JWT. May be an array of string, of which at least one must match
 * @returns void
 */
export function validateCognitoJwtFields(
  payload: JwtPayload,
  options: {
    groups?: string | string[] | null;
    tokenUse?: "id" | "access" | null;
    clientId?: string | string[] | null;
  }
): void {
  // Check groups
  if (options.groups != null) {
    assertStringArraysOverlap(
      "Cognito group",
      payload["cognito:groups"],
      options.groups,
      CognitoJwtInvalidGroupError
    );
  }

  // Check token use
  assertStringArrayContainsString(
    "Token use",
    payload.token_use,
    ["id", "access"] as const,
    CognitoJwtInvalidTokenUseError
  );
  if (options.tokenUse !== null) {
    if (options.tokenUse === undefined) {
      throw new ParameterValidationError(
        "tokenUse must be provided or set to null explicitly"
      );
    }
    assertStringEquals(
      "Token use",
      payload.token_use,
      options.tokenUse,
      CognitoJwtInvalidTokenUseError
    );
  }

  // Check clientId aka audience
  if (options.clientId !== null) {
    if (options.clientId === undefined) {
      throw new ParameterValidationError(
        "clientId must be provided or set to null explicitly"
      );
    }
    if (payload.token_use === "id") {
      assertStringArrayContainsString(
        'Client ID ("audience")',
        payload.aud,
        options.clientId,
        CognitoJwtInvalidClientIdError
      );
    } else {
      assertStringArrayContainsString(
        "Client ID",
        payload.client_id,
        options.clientId,
        CognitoJwtInvalidClientIdError
      );
    }
  }
}

/**
 * Class representing a verifier for JWTs signed by Amazon Cognito
 */
export class CognitoJwtVerifier<
  SpecificVerifyProperties extends Partial<CognitoVerifyProperties>,
  IssuerConfig extends JwtVerifierProperties<SpecificVerifyProperties> & {
    userPoolId: string;
    audience: null;
  },
  MultiIssuer extends boolean,
> extends JwtVerifierBase<SpecificVerifyProperties, IssuerConfig, MultiIssuer> {
  private static USER_POOL_ID_REGEX =
    /^(?<region>[a-z]{2}-(gov-)?[a-z]+-\d)_[a-zA-Z0-9]+$/;

  // Regex for standard issuer format: https://cognito-idp.{region}.amazonaws.com/{userPoolId}
  private static STANDARD_ISSUER_REGEX =
    /^https:\/\/cognito-idp\.(?<region>[a-z]{2}-(gov-)?[a-z]+-\d)\.amazonaws\.com\/(?<userPoolId>[a-z]{2}-(gov-)?[a-z]+-\d_[a-zA-Z0-9]+)$/;

  // Regex for multi-region issuer format: https://issuer.cognito-idp.{region}.amazonaws.com/{userPoolId}
  private static MULTI_REGION_ISSUER_REGEX =
    /^https:\/\/issuer\.cognito-idp\.(?<region>[a-z]{2}-(gov-)?[a-z]+-\d)\.amazonaws\.com\/(?<userPoolId>[a-z]{2}-(gov-)?[a-z]+-\d_[a-zA-Z0-9]+)$/;
  private constructor(
    props: CognitoJwtVerifierProperties | CognitoJwtVerifierMultiProperties[],
    jwksCache?: JwksCache
  ) {
    // Normalize to array for uniform processing
    const propsArray = Array.isArray(props) ? props : [props];
    const issuerConfigs: IssuerConfig[] = [];

    for (const p of propsArray) {
      const parsed = CognitoJwtVerifier.parseUserPoolId(p.userPoolId);
      const baseConfig = {
        ...p,
        userPoolId: p.userPoolId,
        audience: null, // checked instead by validateCognitoJwtFields
      };

      // Register standard issuer config
      issuerConfigs.push({
        ...baseConfig,
        issuer: parsed.issuer,
        jwksUri: parsed.jwksUri,
      } as IssuerConfig);

      // Register multi-region issuer config
      issuerConfigs.push({
        ...baseConfig,
        issuer: parsed.multiRegionIssuer,
        jwksUri: parsed.multiRegionJwksUri,
      } as IssuerConfig);
    }

    super(issuerConfigs, jwksCache);
  }

  /**
   * Parse a User Pool ID, to extract the issuer and JWKS URI for both standard and multi-region formats
   *
   * @param userPoolId The User Pool ID
   * @returns The issuer and JWKS URI for both standard and multi-region formats
   */
  public static parseUserPoolId(userPoolId: string): {
    issuer: string;
    jwksUri: string;
    multiRegionIssuer: string;
    multiRegionJwksUri: string;
  } {
    const match = userPoolId.match(this.USER_POOL_ID_REGEX);
    if (!match) {
      throw new ParameterValidationError(
        `Invalid Cognito User Pool ID: ${userPoolId}`
      );
    }
    const region = match.groups!.region;
    const standardIssuer = `https://cognito-idp.${region}.amazonaws.com/${userPoolId}`;
    const multiRegionIssuer = `https://issuer.cognito-idp.${region}.amazonaws.com/${userPoolId}`;
    return {
      issuer: standardIssuer,
      jwksUri: `${standardIssuer}/.well-known/jwks.json`,
      multiRegionIssuer,
      multiRegionJwksUri: `${multiRegionIssuer}/.well-known/jwks.json`,
    };
  }

  /**
   * Parse a Cognito issuer URL to extract the User Pool ID and determine the format.
   * Supports both standard and multi-region issuer formats.
   *
   * @param issuer The issuer URL from a JWT's iss claim
   * @returns An object containing the userPoolId, region, and format, or null if the issuer is invalid
   */
  public static parseIssuer(issuer: string): {
    userPoolId: string;
    region: string;
    format: "standard" | "multiRegion";
  } | null {
    // Try standard format: https://cognito-idp.{region}.amazonaws.com/{userPoolId}
    const standardMatch = issuer.match(this.STANDARD_ISSUER_REGEX);
    if (standardMatch && standardMatch.groups) {
      const region = standardMatch.groups.region;
      const userPoolId = standardMatch.groups.userPoolId;
      // Validate that the region in the issuer matches the region in the userPoolId
      if (userPoolId.startsWith(`${region}_`)) {
        return {
          region,
          userPoolId,
          format: "standard",
        };
      }
    }

    // Try multi-region format: https://issuer.cognito-idp.{region}.amazonaws.com/{userPoolId}
    const multiRegionMatch = issuer.match(this.MULTI_REGION_ISSUER_REGEX);
    if (multiRegionMatch && multiRegionMatch.groups) {
      const region = multiRegionMatch.groups.region;
      const userPoolId = multiRegionMatch.groups.userPoolId;
      // Validate that the region in the issuer matches the region in the userPoolId
      if (userPoolId.startsWith(`${region}_`)) {
        return {
          region,
          userPoolId,
          format: "multiRegion",
        };
      }
    }

    return null;
  }

  /**
   * Create a Cognito JWT verifier for a single User Pool
   *
   * @param verifyProperties The verification properties for your User Pool
   * @param additionalProperties Additional properties
   * @param additionalProperties.jwksCache Overriding JWKS cache that you want to use
   * @returns An Cognito JWT Verifier instance, that you can use to verify Cognito signed JWTs with
   */
  static create<T extends CognitoJwtVerifierProperties>(
    verifyProperties: T & Partial<CognitoJwtVerifierProperties>,
    additionalProperties?: { jwksCache: JwksCache }
  ): CognitoJwtVerifierSingleUserPool<T>;

  /**
   * Create a Cognito JWT verifier for multiple User Pools
   *
   * @param verifyProperties An array of verification properties, one for each User Pool
   * @param additionalProperties Additional properties
   * @param additionalProperties.jwksCache Overriding JWKS cache that you want to use
   * @returns An Cognito JWT Verifier instance, that you can use to verify Cognito signed JWTs with
   */
  static create<T extends CognitoJwtVerifierMultiProperties>(
    props: (T & Partial<CognitoJwtVerifierMultiProperties>)[],
    additionalProperties?: { jwksCache: JwksCache }
  ): CognitoJwtVerifierMultiUserPool<T>;

  static create(
    verifyProperties:
      | CognitoJwtVerifierProperties
      | CognitoJwtVerifierMultiProperties[],
    additionalProperties?: { jwksCache: JwksCache }
  ) {
    return new this(verifyProperties, additionalProperties?.jwksCache);
  }

  /**
   * Verify (synchronously) a JWT that is signed by Amazon Cognito.
   *
   * @param jwt The JWT, as string
   * @param props Verification properties
   * @returns The payload of the JWT––if the JWT is valid, otherwise an error is thrown
   */
  public verifySync<T extends SpecificVerifyProperties>(
    ...[jwt, properties]: CognitoVerifyParameters<SpecificVerifyProperties>
  ): CognitoIdOrAccessTokenPayload<IssuerConfig, T> {
    const { decomposedJwt, jwksUri, verifyProperties } =
      this.getVerifyParameters(jwt, properties);
    this.verifyDecomposedJwtSync(decomposedJwt, jwksUri, verifyProperties);
    try {
      validateCognitoJwtFields(decomposedJwt.payload, verifyProperties);
    } catch (err) {
      if (
        verifyProperties.includeRawJwtInErrors &&
        err instanceof JwtInvalidClaimError
      ) {
        throw err.withRawJwt(decomposedJwt);
      }
      throw err;
    }
    return decomposedJwt.payload as CognitoIdOrAccessTokenPayload<
      IssuerConfig,
      T
    >;
  }

  /**
   * Verify (asynchronously) a JWT that is signed by Amazon Cognito.
   * This call is asynchronous, and the JWKS will be fetched from the JWKS uri,
   * in case it is not yet available in the cache.
   *
   * @param jwt The JWT, as string
   * @param props Verification properties
   * @returns Promise that resolves to the payload of the JWT––if the JWT is valid, otherwise the promise rejects
   */
  public async verify<T extends SpecificVerifyProperties>(
    ...[jwt, properties]: CognitoVerifyParameters<SpecificVerifyProperties>
  ): Promise<CognitoIdOrAccessTokenPayload<IssuerConfig, T>> {
    const { decomposedJwt, jwksUri, verifyProperties } =
      this.getVerifyParameters(jwt, properties);
    await this.verifyDecomposedJwt(decomposedJwt, jwksUri, verifyProperties);
    try {
      validateCognitoJwtFields(decomposedJwt.payload, verifyProperties);
    } catch (err) {
      if (
        verifyProperties.includeRawJwtInErrors &&
        err instanceof JwtInvalidClaimError
      ) {
        throw err.withRawJwt(decomposedJwt);
      }
      throw err;
    }
    return decomposedJwt.payload as CognitoIdOrAccessTokenPayload<
      IssuerConfig,
      T
    >;
  }

  /**
   * This method loads a JWKS that you provide, into the JWKS cache, so that it is
   * available for JWT verification. Use this method to speed up the first JWT verification
   * (when the JWKS would otherwise have to be downloaded from the JWKS uri), or to provide the JWKS
   * in case the JwtVerifier does not have internet access to download the JWKS
   *
   * @param jwks The JWKS
   * @param userPoolId The userPoolId for which you want to cache the JWKS
   *  Supply this field, if you instantiated the CognitoJwtVerifier with multiple userPoolIds
   * @returns void
   */
  public cacheJwks(
    ...[jwks, userPoolId]: MultiIssuer extends false
      ? [jwks: Jwks, userPoolId?: string]
      : [jwks: Jwks, userPoolId: string]
  ): void {
    // Get unique User Pool IDs from the issuer configs
    const uniqueUserPoolIds = new Set<string>();
    for (const config of this.issuersConfig.values()) {
      if ((config as IssuerConfig & { userPoolId: string }).userPoolId) {
        uniqueUserPoolIds.add(
          (config as IssuerConfig & { userPoolId: string }).userPoolId
        );
      }
    }

    // Determine which User Pool to cache for
    let targetUserPoolId: string;
    if (userPoolId !== undefined) {
      targetUserPoolId = userPoolId;
    } else if (uniqueUserPoolIds.size > 1) {
      throw new ParameterValidationError("userPoolId must be provided");
    } else if (uniqueUserPoolIds.size === 1) {
      targetUserPoolId = uniqueUserPoolIds.values().next().value!;
    } else {
      throw new ParameterValidationError("No User Pool configured");
    }

    // Parse the User Pool ID to get both issuer formats
    const parsed = CognitoJwtVerifier.parseUserPoolId(targetUserPoolId);

    // Cache JWKS for both standard and multi-region issuers
    const standardConfig = this.getIssuerConfig(parsed.issuer);
    const multiRegionConfig = this.getIssuerConfig(parsed.multiRegionIssuer);

    super.cacheJwks(jwks, standardConfig.issuer);
    super.cacheJwks(jwks, multiRegionConfig.issuer);
  }
}
