import { AwsAlbJwksCache } from "./alb-v2";
import { assertStringArrayContainsString } from "./assert";
import { JwtInvalidClaimError } from "./error";
import { JwksCache } from "./jwk";
import { DecomposedJwt, decomposeUnverifiedJwt } from "./jwt";
import { JwtHeader, JwtPayload } from "./jwt-model";
import { JwtVerifierBase, JwtVerifierProperties } from "./jwt-verifier";
import { JsonObject } from "./safe-json-parse";
import { Properties } from "./typing-util";

export class JwtInvalidSignerError extends JwtInvalidClaimError {}

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

    /**
     * If you want to peek inside the invalid JWT when verification fails, set `includeRawJwtInErrors` to true.
     * Then, if an error is thrown during verification of the invalid JWT (e.g. the JWT is invalid because it is expired),
     * the Error object will include a property `rawJwt`, with the raw decoded contents of the **invalid** JWT.
     * The `rawJwt` will only be included in the Error object, if the JWT's signature can at least be verified.
     */
    includeRawJwtInErrors?: boolean;
  
}


/** Type for Alb JWT verifier properties, for a single Alb */
export type AlbJwtVerifierProperties = {

} & Partial<AlbVerifyProperties>;

/**
 * Type for Alb JWT verifier properties, when multiple Alb are used in the verifier.
 */
export type AlbJwtVerifierMultiProperties = {

} & AlbVerifyProperties;

export type AlbJwtVerifierSingleAlb<
  T extends AlbJwtVerifierProperties,
> = AlbJwtVerifier<
  Properties<AlbVerifyProperties, T>,
  T &
    JwtVerifierProperties<AlbVerifyProperties> & {
      userPoolId: string;
      audience: null;
    },
  false
>;

export type AlbJwtVerifierMultiAlb<
  T extends AlbJwtVerifierMultiProperties,
> = AlbJwtVerifier<
  Properties<AlbVerifyProperties, T>,
  T &
    JwtVerifierProperties<AlbVerifyProperties> & {
      userPoolId: string;
      audience: null;
    },
  true
>;

type AlbVerifyParameters<SpecificVerifyProperties> = {
  [key: string]: never;
} extends SpecificVerifyProperties
  ? [jwt: string, props?: SpecificVerifyProperties]
  : [jwt: string, props: SpecificVerifyProperties];

type DataTokenPayload = {
    exp:number
    iss:string,
} & JsonObject;

export class AlbJwtVerifier<
  SpecificVerifyProperties extends Partial<AlbVerifyProperties>,
  IssuerConfig extends JwtVerifierProperties<SpecificVerifyProperties> & {
    audience: null;
  },
  MultiIssuer extends boolean,
> extends JwtVerifierBase<SpecificVerifyProperties, IssuerConfig, MultiIssuer> {

  private readonly defaultJwksUri;

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
      const region = "us-east-1";//TODO extract region
      this.defaultJwksUri = `https://public-keys.auth.elb.${region}.amazonaws.com`;
    }

  static create<T extends AlbJwtVerifierProperties>(
    verifyProperties: T & Partial<AlbJwtVerifierProperties>,
    additionalProperties?: { jwksCache: JwksCache }
  ): AlbJwtVerifierSingleAlb<T>;


  static create<T extends AlbJwtVerifierMultiProperties>(
    props: (T & Partial<AlbJwtVerifierMultiProperties>)[],
    additionalProperties?: { jwksCache: JwksCache }
  ): AlbJwtVerifierMultiAlb<T>;

  // eslint-disable-next-line @typescript-eslint/explicit-module-boundary-types
  static create(
    verifyProperties:
      | AlbJwtVerifierProperties
      | AlbJwtVerifierMultiProperties[]
  ) {
    return new this(verifyProperties);
  }
  
  public verifySync(
    ...[jwt, properties]: AlbVerifyParameters<SpecificVerifyProperties>
  ): DataTokenPayload {
    const { decomposedJwt, jwksUri, verifyProperties } =
      this.getVerifyParameters(jwt, properties);
    this.verifyDecomposedJwtSync(decomposedJwt, jwksUri, verifyProperties);
    try {
      this.validateDataJwtFields(decomposedJwt.header, decomposedJwt.payload, verifyProperties);
    } catch (err) {
      if (
        verifyProperties.includeRawJwtInErrors &&
        err instanceof JwtInvalidClaimError
      ) {
        throw err.withRawJwt(decomposedJwt);
      }
      throw err;
    }
    return decomposedJwt.payload as DataTokenPayload;
  }

  public async verify(
    ...[jwt, properties]: AlbVerifyParameters<SpecificVerifyProperties>
  ): Promise<DataTokenPayload> {
    const { decomposedJwt, jwksUri, verifyProperties } =
      this.getVerifyParameters(jwt, properties);
    await this.verifyDecomposedJwt(decomposedJwt, jwksUri, verifyProperties);
    try {
      this.validateDataJwtFields(decomposedJwt.header, decomposedJwt.payload, verifyProperties);
    } catch (err) {
      if (
        verifyProperties.includeRawJwtInErrors &&
        err instanceof JwtInvalidClaimError
      ) {
        throw err.withRawJwt(decomposedJwt);
      }
      throw err;
    }
    return decomposedJwt.payload as DataTokenPayload;
  }

  protected getVerifyParameters(
    jwt: string,
    verifyProperties?: Partial<SpecificVerifyProperties>
  ): {
    decomposedJwt: DecomposedJwt;
    jwksUri: string;
    verifyProperties: SpecificVerifyProperties;
  } {
    const decomposedJwt = decomposeUnverifiedJwt(jwt);
    assertStringArrayContainsString(
      "Signer",
      decomposedJwt.header.signer,
      this.expectedIssuers,
      JwtInvalidSignerError
    );
    const albConfig = this.getIssuerConfig(decomposedJwt.header.signer);
    return {
      decomposedJwt,
      jwksUri: verifyProperties?.jwksUri ?? this.defaultJwksUri,
      verifyProperties: {
        ...albConfig,
        ...verifyProperties,
      } as unknown as SpecificVerifyProperties,
    };
  }
 
  private validateDataJwtFields(
    header:JwtHeader,
    payload: JwtPayload,
    options: {
      clientId?: string | string[] | null;
    }
  ): void {
    //TODO  check client header, signer header, iss payload
  }

}