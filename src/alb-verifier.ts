import { AwsAlbJwksCache } from "./alb-v2";
import { JwksCache } from "./jwk";
import { JwtVerifierBase, JwtVerifierProperties } from "./jwt-verifier";
import { Properties } from "./typing-util";

export interface AlbVerifyProperties {

    /**
     * The client ID that you expect to be present on the JWT
     * (In the ID token's aud claim, or the Access token's client_id claim).
     * If you provide a string array, that means at least one of those client IDs
     * must be present on the JWT.
     * Pass null explicitly to not check the JWT's client ID--if you know what you're doing
     */
    clientId: string | string[] | null;

    loadBalancerArn: string;

    jwksUri?: string;
    issuer: string;
  
}


/** Type for Cognito JWT verifier properties, for a single User Pool */
export type AlbJwtVerifierProperties = {

} & Partial<AlbVerifyProperties>;

/**
 * Type for Cognito JWT verifier properties, when multiple User Pools are used in the verifier.
 * In this case, you should be explicit in mapping `clientId` to User Pool.
 */
export type AlbJwtVerifierMultiProperties = {

} & AlbVerifyProperties;


/**
 * TODO rename
 */
export type AlbJwtVerifierSingleUserPool<
  T extends AlbJwtVerifierProperties,
> = AlbJwtVerifier<
  Properties<AlbVerifyProperties, T>,
  T &
    JwtVerifierProperties<AlbVerifyProperties> & {
      audience: null;
    },
  false
>;

/**
 * TODO rename
 */
export type AlbJwtVerifierMultiUserPool<
  T extends AlbJwtVerifierMultiProperties,
> = AlbJwtVerifier<
  Properties<AlbVerifyProperties, T>,
  T &
    JwtVerifierProperties<AlbVerifyProperties> & {
      audience: null;
    },
  true
>;


export class AlbJwtVerifier<
  SpecificVerifyProperties extends Partial<AlbVerifyProperties>,
  IssuerConfig extends JwtVerifierProperties<SpecificVerifyProperties> & {
    audience: null;
  },
  MultiIssuer extends boolean,
> extends JwtVerifierBase<SpecificVerifyProperties, IssuerConfig, MultiIssuer> {

    private constructor(
        props: AlbJwtVerifierProperties | AlbJwtVerifierMultiProperties[],
      ) {
        const issuerConfig = Array.isArray(props)
      ? (props.map((p) => ({
          ...p,
          audience: null, // checked instead by validateCognitoJwtFields
        })) as IssuerConfig[])
      : ({
          ...props,
          audience: null, // checked instead by validateCognitoJwtFields
        } as IssuerConfig);
        super(issuerConfig, new AwsAlbJwksCache());
      }

      
  /**
   * Create a Cognito JWT verifier for a single User Pool
   *
   * @param verifyProperties The verification properties for your User Pool
   * @param additionalProperties Additional properties
   * @param additionalProperties.jwksCache Overriding JWKS cache that you want to use
   * @returns An Cognito JWT Verifier instance, that you can use to verify Cognito signed JWTs with
   */
  static create<T extends AlbJwtVerifierProperties>(
    verifyProperties: T & Partial<AlbJwtVerifierProperties>,
    additionalProperties?: { jwksCache: JwksCache }
  ): AlbJwtVerifierSingleUserPool<T>;


  static create<T extends AlbJwtVerifierMultiProperties>(
    props: (T & Partial<AlbJwtVerifierMultiProperties>)[],
    additionalProperties?: { jwksCache: JwksCache }
  ): AlbJwtVerifierMultiUserPool<T>;


  // eslint-disable-next-line @typescript-eslint/explicit-module-boundary-types
  static create(
    verifyProperties:
      | AlbJwtVerifierProperties
      | AlbJwtVerifierMultiProperties[]
  ) {
    return new this(verifyProperties);
  }
 
}