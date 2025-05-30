import { AlbJwksCache } from "./alb-cache.js";
import { assertStringArrayContainsString } from "./assert.js";
import {
  AlbJwtInvalidClientIdError,
  AlbJwtInvalidSignerError,
  JwtInvalidClaimError,
  ParameterValidationError,
} from "./error.js";
import { Jwk, JwksCache } from "./jwk.js";
import { AlbJwtHeader, AlbJwtPayload, JwtHeader } from "./jwt-model.js";
import { JwtVerifierBase, JwtVerifierProperties } from "./jwt-verifier.js";
import { Properties } from "./typing-util.js";

const ALB_ARN_REGEX =
  /^arn:(?:aws|aws-cn):elasticloadbalancing:([a-z]{2}-(?:gov-)?[a-z]+-\d{1}):.+$/;

type AlbArn = {
  region: string;
};

export interface AlbVerifyProperties {
  /**
   * The client ID that you expect to be present in the JWT's client claim (in the JWT header).
   * If you provide a string array, that means at least one of those client IDs
   * must be present in the JWT's client claim.
   * Pass null explicitly to not check the JWT's client ID--if you know what you're doing
   */
  clientId: string | string[] | null;
  /**
   * The number of seconds after expiration (exp claim) or before not-before (nbf claim) that you will allow
   * (use this to account for clock differences between systems)
   */
  graceSeconds?: number;
  /**
   * Your custom function with checks. It will be called, at the end of the verification,
   * after standard verification checks have all passed.
   * Throw an error in this function if you want to reject the JWT for whatever reason you deem fit.
   * Your function will be called with a properties object that contains:
   * - the decoded JWT header
   * - the decoded JWT payload
   * - the JWK that was used to verify the JWT's signature
   */
  customJwtCheck?: (props: {
    header: AlbJwtHeader;
    payload: AlbJwtPayload;
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

/** Type for JWT verifier properties, for a single issuer */
export type AlbJwtVerifierProperties = {
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
  issuer: string | null;
  /**
   * The ARN of the Application Load Balancer (ALB) that signs the JWT.
   * Set this to the expected value of the `signer` claim in the JWT (JWT header).
   * If you provide a string array, that means at least one of those ALB ARNs
   * must be present in the JWT's signer claim.
   */
  albArn: string | string[];
} & Partial<AlbVerifyProperties>;

/**
 * Type for JWT verifier properties, when multiple issuers are used in the verifier.
 * In this case, you should be explicit in mapping audience to issuer.
 */
export type AlbJwtVerifierMultiProperties = {
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
  issuer: string | null;
  /**
   * The ARN of the Application Load Balancer (ALB) that signs the JWT.
   * Set this to the expected value of the `signer` claim in the JWT (JWT header).
   * If you provide a string array, that means at least one of those ALB ARNs
   * must be present in the JWT's signer claim.
   */
  albArn: string | string[];
} & AlbVerifyProperties;

/**
 * ALB JWT Verifier for a single issuer
 */
export type AlbJwtVerifierSingleUserPool<T extends AlbJwtVerifierProperties> =
  AlbJwtVerifier<
    Properties<AlbVerifyProperties, T>,
    T &
      JwtVerifierProperties<AlbVerifyProperties> & {
        albArn: string | string[];
        audience: null;
      },
    false
  >;

/**
 * ALB JWT Verifier for multiple issuer
 */
export type AlbJwtVerifierMultiUserPool<
  T extends AlbJwtVerifierMultiProperties,
> = AlbJwtVerifier<
  Properties<AlbVerifyProperties, T>,
  T &
    JwtVerifierProperties<AlbVerifyProperties> & {
      albArn: string | string[];
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
type AlbVerifyParameters<SpecificVerifyProperties> = {
  [key: string]: never;
} extends SpecificVerifyProperties
  ? [jwt: string, props?: SpecificVerifyProperties]
  : [jwt: string, props: SpecificVerifyProperties];

/**
 * Class representing a verifier for JWTs signed by AWS ALB
 */
export class AlbJwtVerifier<
  SpecificVerifyProperties extends Partial<AlbVerifyProperties>,
  IssuerConfig extends JwtVerifierProperties<SpecificVerifyProperties> & {
    audience: null;
    albArn: string | string[];
  },
  MultiIssuer extends boolean,
> extends JwtVerifierBase<SpecificVerifyProperties, IssuerConfig, MultiIssuer> {
  private constructor(
    props: AlbJwtVerifierProperties | AlbJwtVerifierMultiProperties[],
    jwksCache: JwksCache
  ) {
    const transformPropertiesToIssuerConfig = (
      props: AlbJwtVerifierProperties
    ) => {
      const albArns = validateAndParseAlbArns(props.albArn);
      return {
        jwksUri: props.jwksUri ?? getDefaultJwksUri(albArns),
        ...props,
        audience: null,
      } as IssuerConfig;
    };

    const issuerConfig = Array.isArray(props)
      ? props.map(transformPropertiesToIssuerConfig)
      : transformPropertiesToIssuerConfig(props);

    super(issuerConfig, jwksCache);
  }

  /**
   * Create an JWT verifier for a single issuer
   *
   * @param verifyProperties The verification properties for your issuer
   * @param additionalProperties Additional properties
   * @param additionalProperties.jwksCache Overriding JWKS cache that you want to use
   * @returns An JWT Verifier instance, that you can use to verify JWTs with
   */
  static create<T extends AlbJwtVerifierProperties>(
    verifyProperties: T & Partial<AlbJwtVerifierProperties>,
    additionalProperties?: { jwksCache: JwksCache }
  ): AlbJwtVerifierSingleUserPool<T>;

  /**
   * Create a JWT verifier for multiple issuer
   *
   * @param verifyProperties An array of verification properties, one for each issuer
   * @param additionalProperties Additional properties
   * @param additionalProperties.jwksCache Overriding JWKS cache that you want to use
   * @returns A JWT Verifier instance, that you can use to verify JWTs with
   */
  static create<T extends AlbJwtVerifierMultiProperties>(
    props: (T & Partial<AlbJwtVerifierMultiProperties>)[],
    additionalProperties?: { jwksCache: JwksCache }
  ): AlbJwtVerifierMultiUserPool<T>;

  static create(
    verifyProperties:
      | AlbJwtVerifierProperties
      | AlbJwtVerifierMultiProperties[],
    additionalProperties?: { jwksCache: JwksCache }
  ) {
    return new this(
      verifyProperties,
      additionalProperties?.jwksCache ?? new AlbJwksCache()
    );
  }

  /**
   * Verify (synchronously) a JWT that is signed by AWS Application Load Balancer.
   *
   * @param jwt The JWT, as string
   * @param props Verification properties
   * @returns The payload of the JWT––if the JWT is valid, otherwise an error is thrown
   */
  public verifySync(
    ...[jwt, properties]: AlbVerifyParameters<SpecificVerifyProperties>
  ): AlbJwtPayload {
    const { decomposedJwt, jwksUri, verifyProperties } =
      this.getVerifyParameters(jwt, properties);
    try {
      this.verifyDecomposedJwtSync(decomposedJwt, jwksUri, verifyProperties);
      validateAlbJwtFields(decomposedJwt.header, verifyProperties);
    } catch (err) {
      if (
        verifyProperties.includeRawJwtInErrors &&
        err instanceof JwtInvalidClaimError
      ) {
        throw err.withRawJwt(decomposedJwt);
      }
      throw err;
    }
    return decomposedJwt.payload as AlbJwtPayload;
  }

  /**
   * Verify (asynchronously) a JWT that is signed by AWS Application Load Balancer.
   * This call is asynchronous, and the JWKS will be fetched from the JWKS uri,
   * in case it is not yet available in the cache.
   *
   * @param jwt The JWT, as string
   * @param props Verification properties
   * @returns Promise that resolves to the payload of the JWT––if the JWT is valid, otherwise the promise rejects
   */
  public async verify(
    ...[jwt, properties]: AlbVerifyParameters<SpecificVerifyProperties>
  ): Promise<AlbJwtPayload> {
    const { decomposedJwt, jwksUri, verifyProperties } =
      this.getVerifyParameters(jwt, properties);
    try {
      await this.verifyDecomposedJwt(decomposedJwt, jwksUri, verifyProperties);
      validateAlbJwtFields(decomposedJwt.header, verifyProperties);
    } catch (err) {
      if (
        verifyProperties.includeRawJwtInErrors &&
        err instanceof JwtInvalidClaimError
      ) {
        throw err.withRawJwt(decomposedJwt);
      }
      throw err;
    }
    return decomposedJwt.payload as AlbJwtPayload;
  }
}

export function validateAlbJwtFields(
  header: JwtHeader,
  options: {
    clientId?: string | string[] | null;
    albArn: string | string[];
  }
): void {
  // Check ALB ARN (signer)
  assertStringArrayContainsString(
    "ALB ARN",
    header.signer,
    options.albArn,
    AlbJwtInvalidSignerError
  );
  // Check clientId
  if (options.clientId !== null) {
    if (options.clientId === undefined) {
      throw new ParameterValidationError(
        "clientId must be provided or set to null explicitly"
      );
    }
    assertStringArrayContainsString(
      "Client ID",
      header.client,
      options.clientId,
      AlbJwtInvalidClientIdError
    );
  }
}

export function validateAndParseAlbArns(albArn: string | string[]): AlbArn[] {
  if (Array.isArray(albArn)) {
    return albArn.map(parseAlbArn);
  } else {
    return [parseAlbArn(albArn)];
  }
}

function parseAlbArn(albArn: string): AlbArn {
  const match = ALB_ARN_REGEX.exec(albArn);
  if (!match) {
    throw new ParameterValidationError(`Invalid load balancer ARN: ${albArn}`);
  }
  return {
    region: match[1],
  };
}

function getDefaultJwksUri(albArns: AlbArn[]): string {
  const regions = albArns.map((arn) => arn.region);
  const uniqueRegions = Array.from(new Set(regions));
  if (uniqueRegions.length > 1) {
    throw new ParameterValidationError(
      "Using ALBs from different regions is not supported for the same issuer"
    );
  }
  return `https://public-keys.auth.elb.${uniqueRegions[0]}.amazonaws.com`;
}
