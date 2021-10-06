// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { ParameterValidationError } from "./error.js";
import { JwtRsaVerifierBase, JwtRsaVerifierProperties } from "./jwt-rsa.js";
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
import {
  StillToProvideVerifyProps,
  WithoutOptionalFields,
} from "./typing-util.js";

interface CognitoVerifyProperties {
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
}

/** Interface for Cognito JWT verifier properties, for a single User Pool */
interface CognitoJwtVerifierProperties
  extends Partial<CognitoVerifyProperties> {
  /** The User Pool whose JWTs you want to verify */
  userPoolId: string;
}

/**
 * Interface for Cognito JWT verifier properties, when multiple User Pools are used in the verifier.
 * In this case, you should be explicit in mapping `clientId` to User Pool.
 */
interface CognitoJwtVerifierMultiProperties extends CognitoVerifyProperties {
  /** The User Pool whose JWTs you want to verify */
  userPoolId: string;
}

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
function validateCognitoJwtFields(
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
      options.groups
    );
  }

  // Check token use
  assertStringArrayContainsString("Token use", payload.token_use, [
    "id",
    "access",
  ]);
  if (options.tokenUse !== null) {
    if (options.tokenUse === undefined) {
      throw new ParameterValidationError(
        "tokenUse must be provided or set to null explicitly"
      );
    }
    assertStringEquals("Token use", payload.token_use, options.tokenUse);
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
        options.clientId
      );
    } else {
      assertStringArrayContainsString(
        "Client ID",
        payload.client_id,
        options.clientId
      );
    }
  }
}

/**
 * Class representing a verifier for JWTs signed by Amazon Cognito
 */
export class CognitoJwtVerifier<
  StillToProvide extends Partial<CognitoVerifyProperties>,
  IssuerConfig extends JwtRsaVerifierProperties & CognitoJwtVerifierProperties,
  MultiIssuer extends boolean
> extends JwtRsaVerifierBase<
  StillToProvide,
  CognitoVerifyProperties,
  IssuerConfig,
  MultiIssuer
> {
  private constructor(
    props: CognitoJwtVerifierProperties | CognitoJwtVerifierMultiProperties[],
    jwksCache?: JwksCache
  ) {
    const issuerConfig = Array.isArray(props)
      ? (props.map((p) => ({
          ...p,
          ...CognitoJwtVerifier.parseUserPoolId(p.userPoolId),
          audience: null, // checked instead by validateCognitoJwtFields
        })) as IssuerConfig[])
      : ({
          ...props,
          ...CognitoJwtVerifier.parseUserPoolId(props.userPoolId),
          audience: null, // checked instead by validateCognitoJwtFields
        } as IssuerConfig);
    super(issuerConfig, jwksCache);
  }

  /**
   * Parse a User Pool ID, to extract the issuer and JWKS URI
   *
   * @param userPoolId The User Pool ID
   * @returns The issuer and JWKS URI for the User Pool
   */
  public static parseUserPoolId(userPoolId: string): {
    issuer: string;
    jwksUri: string;
  } {
    // Disable safe regexp check as userPoolId is provided by developer, i.e. is not user input
    // eslint-disable-next-line security/detect-unsafe-regex
    const match = userPoolId.match(/^(?<region>(\w+-)?\w+-\w+-\d)+_\w+$/);
    if (!match) {
      throw new ParameterValidationError(
        `Invalid Cognito User Pool ID: ${userPoolId}`
      );
    }
    const region = match.groups!.region;
    const issuer = `https://cognito-idp.${region}.amazonaws.com/${userPoolId}`;
    return {
      issuer,
      jwksUri: `${issuer}/.well-known/jwks.json`,
    };
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
    props: T,
    additionalProperties?: { jwksCache: JwksCache }
  ): CognitoJwtVerifier<
    StillToProvideVerifyProps<
      WithoutOptionalFields<CognitoVerifyProperties>,
      typeof props
    > &
      Partial<CognitoVerifyProperties>,
    T & JwtRsaVerifierProperties,
    false
  >;

  /**
   * Create a Cognito JWT verifier for multiple User Pools
   *
   * @param verifyProperties An array of verification properties, one for each User Pool
   * @param additionalProperties Additional properties
   * @param additionalProperties.jwksCache Overriding JWKS cache that you want to use
   * @returns An Cognito JWT Verifier instance, that you can use to verify Cognito signed JWTs with
   */
  static create<T extends CognitoJwtVerifierMultiProperties>(
    props: T[],
    additionalProperties?: { jwksCache: JwksCache }
  ): CognitoJwtVerifier<
    Partial<CognitoVerifyProperties>,
    T & JwtRsaVerifierProperties,
    true
  >;

  // eslint-disable-next-line @typescript-eslint/explicit-module-boundary-types
  static create(
    props: CognitoJwtVerifierProperties | CognitoJwtVerifierMultiProperties[],
    additionalProperties?: { jwksCache: JwksCache }
  ) {
    return new this(props, additionalProperties?.jwksCache);
  }

  /**
   * Verify (synchronously) a JWT that is signed by Amazon Cognito.
   *
   * @param jwt The JWT, as string
   * @param props Verification properties
   * @returns The payload of the JWT––if the JWT is valid, otherwise an error is thrown
   */
  public verifySync<
    OptionalProps extends Partial<CognitoVerifyProperties>,
    MandatoryProps extends StillToProvide
  >(
    ...args: { [key: string]: never } extends StillToProvide
      ? [jwt: string, props?: OptionalProps]
      : [jwt: string, props: MandatoryProps]
  ): CognitoIdOrAccessTokenPayload<
    IssuerConfig,
    { [key: string]: never } extends StillToProvide
      ? OptionalProps
      : MandatoryProps
  > {
    const payload = super.verifySync(...args);
    const issuerConfig = this.getIssuerConfig(payload.iss);
    const verifyProperties = {
      ...issuerConfig,
      ...args[1],
    };
    validateCognitoJwtFields(payload, verifyProperties);
    return payload as CognitoIdOrAccessTokenPayload<
      IssuerConfig,
      { [key: string]: never } extends StillToProvide
        ? OptionalProps
        : MandatoryProps
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
  public async verify<
    OptionalProps extends Partial<CognitoVerifyProperties>,
    MandatoryProps extends StillToProvide
  >(
    ...args: { [key: string]: never } extends StillToProvide
      ? [jwt: string, props?: OptionalProps]
      : [jwt: string, props: MandatoryProps]
  ): Promise<
    CognitoIdOrAccessTokenPayload<
      IssuerConfig,
      { [key: string]: never } extends StillToProvide
        ? OptionalProps
        : MandatoryProps
    >
  > {
    const payload = await super.verify(...args);
    const issuerConfig = this.getIssuerConfig(payload.iss);
    const verifyProperties = {
      ...issuerConfig,
      ...args[1],
    };
    validateCognitoJwtFields(payload, verifyProperties);
    return payload as CognitoIdOrAccessTokenPayload<
      IssuerConfig,
      { [key: string]: never } extends StillToProvide
        ? OptionalProps
        : MandatoryProps
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
    ...args: MultiIssuer extends false
      ? [jwks: Jwks, userPoolId?: string]
      : [jwks: Jwks, userPoolId: string]
  ): void {
    let issuer: string | undefined;
    if (args[1] !== undefined) {
      issuer = CognitoJwtVerifier.parseUserPoolId(args[1]).issuer;
    } else if (this.expectedIssuers.length > 1) {
      throw new ParameterValidationError("userPoolId must be provided");
    }
    const issuerConfig = this.getIssuerConfig(issuer);
    super.cacheJwks(args[0], issuerConfig.issuer);
  }
}
