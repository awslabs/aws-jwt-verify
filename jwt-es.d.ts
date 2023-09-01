import { JwksCache, Jwk, EsSignatureJwk, Jwks } from "./jwk.js";
import { JwtHeader, JwtPayload } from "./jwt-model.js";
import { AsAsync, Properties } from "./typing-util.js";
import { DecomposedJwt } from "./jwt.js";
export declare const supportedSignatureAlgorithms: readonly ["ES256", "ES384", "ES512"];
export type SupportedSignatureAlgorithm = typeof supportedSignatureAlgorithms[number];
/** Interface for JWT verification properties */
export interface VerifyProperties {
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
    /**
     * If you want to peek inside the invalid JWT when verification fails, set `includeRawJwtInErrors` to true.
     * Then, if an error is thrown during verification of the invalid JWT (e.g. the JWT is invalid because it is expired),
     * the Error object will include a property `rawJwt`, with the raw decoded contents of the **invalid** JWT.
     * The `rawJwt` will only be included in the Error object, if the JWT's signature can at least be verified.
     */
    includeRawJwtInErrors?: boolean;
}
/** Type for JWT ES verifier properties, for a single issuer */
export type JwtEsVerifierProperties<VerifyProps> = {
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
} & Partial<VerifyProps>;
/**
 * Type for JWT ES verifier properties, when multiple issuers are used in the verifier.
 * In this case, you should be explicit in mapping audience to issuer.
 */
export type JwtEsVerifierMultiProperties<T> = {
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
} & T;
/**
 * JWT Verifier (ES) for a single issuer
 */
export type JwtEsVerifierSingleIssuer<T extends JwtEsVerifierProperties<VerifyProperties>> = JwtEsVerifier<Properties<VerifyProperties, T>, T & JwtEsVerifierProperties<VerifyProperties>, false>;
/**
 * Parameters used for verification of a JWT.
 * The first parameter is the JWT, which is (of course) mandatory.
 * The second parameter is an object with specific properties to use during verification.
 * The second parameter is only mandatory if its mandatory members (e.g. audience) were not
 *  yet provided at verifier level. In that case, they must now be provided.
 */
type VerifyParameters<SpecificVerifyProperties> = {
    [key: string]: never;
} extends SpecificVerifyProperties ? [jwt: string, props?: SpecificVerifyProperties] : [jwt: string, props: SpecificVerifyProperties];
/**
 * JWT Verifier (ES) for multiple issuers
 */
export type JwtEsVerifierMultiIssuer<T extends JwtEsVerifierMultiProperties<VerifyProperties>> = JwtEsVerifier<Properties<VerifyProperties, T>, T & JwtEsVerifierProperties<VerifyProperties>, true>;
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
export type JwsVerificationFunctionSync = (props: {
    keyObject: GenericKeyObject;
    alg: SupportedSignatureAlgorithm;
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
export type JwsVerificationFunctionAsync = AsAsync<JwsVerificationFunctionSync>;
/**
 * Verify a JWT asynchronously (thus allowing for the JWKS to be fetched from the JWKS URI)
 *
 * @param jwt The JWT
 * @param jwksUri The JWKS URI, where the JWKS can be fetched from
 * @param options Verification options
 * @returns Promise that resolves to the payload of the JWT––if the JWT is valid, otherwise the promise rejects
 */
export declare function verifyJwt(jwt: string, jwksUri: string, options: {
    issuer: string | string[] | null;
    audience: string | string[] | null;
    scope?: string | string[];
    graceSeconds?: number;
    customJwtCheck?: (props: {
        header: JwtHeader;
        payload: JwtPayload;
        jwk: Jwk;
    }) => Promise<void> | void;
    includeRawJwtInErrors?: boolean;
}): Promise<JwtPayload>;
/**
 * Verify a JWT synchronously, using a JWKS or JWK that has already been fetched
 *
 * @param jwt The JWT
 * @param jwkOrJwks The JWKS that includes the right JWK (indexed by kid). Alternatively, provide the right JWK directly
 * @param options Verification options
 * @param transformJwkToKeyObjectFn A function that can transform a JWK into a crypto native key object
 * @returns The (JSON parsed) payload of the JWT––if the JWT is valid, otherwise an error is thrown
 */
export declare function verifyJwtSync(jwt: string, jwkOrJwks: Jwk | Jwks, options: {
    issuer: string | string[] | null;
    audience: string | string[] | null;
    scope?: string | string[];
    graceSeconds?: number;
    customJwtCheck?: (props: {
        header: JwtHeader;
        payload: JwtPayload;
        jwk: Jwk;
    }) => void;
    includeRawJwtInErrors?: boolean;
}, transformJwkToKeyObjectFn?: JwkToKeyObjectTransformerSync): JwtPayload;
/** Type alias for better readability below */
type Issuer = string;
/**
 * Abstract class representing a verifier for JWTs signed with ES (e.g. ES256, ES384, ES512)
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
export declare abstract class JwtEsVerifierBase<SpecificVerifyProperties extends Record<string | number, unknown>, IssuerConfig extends JwtEsVerifierProperties<SpecificVerifyProperties>, MultiIssuer extends boolean> {
    private jwksCache;
    private issuersConfig;
    private publicKeyCache;
    protected constructor(verifyProperties: IssuerConfig | IssuerConfig[], jwksCache?: JwksCache);
    protected get expectedIssuers(): string[];
    protected getIssuerConfig(issuer?: string): IssuerConfig & {
        jwksUri: string;
    };
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
    cacheJwks(...[jwks, issuer]: MultiIssuer extends false ? [jwks: Jwks, issuer?: string] : [jwks: Jwks, issuer: string]): void;
    /**
     * Hydrate the JWKS cache for (all of) the configured issuer(s).
     * This will fetch and cache the latest and greatest JWKS for concerned issuer(s).
     *
     * @param issuer The issuer to fetch the JWKS for
     * @returns void
     */
    hydrate(): Promise<void>;
    /**
     * Verify (synchronously) a JWT that is signed using RS256 / RS384 / RS512.
     *
     * @param jwt The JWT, as string
     * @param props Verification properties
     * @returns The payload of the JWT––if the JWT is valid, otherwise an error is thrown
     */
    verifySync(...[jwt, properties]: VerifyParameters<SpecificVerifyProperties>): JwtPayload;
    /**
     * Verify (synchronously) an already decomposed JWT, that is signed using RS256 / RS384 / RS512.
     *
     * @param decomposedJwt The decomposed Jwt
     * @param jwk The JWK to verify the JWTs signature with
     * @param verifyProperties The properties to use for verification
     * @returns The payload of the JWT––if the JWT is valid, otherwise an error is thrown
     */
    protected verifyDecomposedJwtSync(decomposedJwt: DecomposedJwt, jwksUri: string, verifyProperties: SpecificVerifyProperties): JwtPayload;
    /**
     * Verify (asynchronously) a JWT that is signed using RS256 / RS384 / RS512.
     * This call is asynchronous, and the JWKS will be fetched from the JWKS uri,
     * in case it is not yet available in the cache.
     *
     * @param jwt The JWT, as string
     * @param props Verification properties
     * @returns Promise that resolves to the payload of the JWT––if the JWT is valid, otherwise the promise rejects
     */
    verify(...[jwt, properties]: VerifyParameters<SpecificVerifyProperties>): Promise<JwtPayload>;
    /**
     * Verify (asynchronously) an already decomposed JWT, that is signed using RS256 / RS384 / RS512.
     *
     * @param decomposedJwt The decomposed Jwt
     * @param jwk The JWK to verify the JWTs signature with
     * @param verifyProperties The properties to use for verification
     * @returns The payload of the JWT––if the JWT is valid, otherwise an error is thrown
     */
    protected verifyDecomposedJwt(decomposedJwt: DecomposedJwt, jwksUri: string, verifyProperties: SpecificVerifyProperties): Promise<JwtPayload>;
    /**
     * Get the verification parameters to use, by merging the issuer configuration,
     * with the overriding properties that are now provided
     *
     * @param jwt: the JWT that is going to be verified
     * @param verifyProperties: the overriding properties, that override the issuer configuration
     * @returns The merged verification parameters
     */
    protected getVerifyParameters(jwt: string, verifyProperties?: Partial<SpecificVerifyProperties>): {
        decomposedJwt: DecomposedJwt;
        jwksUri: string;
        verifyProperties: SpecificVerifyProperties;
    };
    /**
     * Get issuer config with JWKS URI, by adding a default JWKS URI if needed
     *
     * @param config: the issuer config.
     * @returns The config with JWKS URI
     */
    private withJwksUri;
}
/**
 * Class representing a verifier for JWTs signed with ES (e.g. ES256 / ES384 / ES512)
 */
export declare class JwtEsVerifier<SpecificVerifyProperties extends Partial<VerifyProperties>, IssuerConfig extends JwtEsVerifierProperties<SpecificVerifyProperties>, MultiIssuer extends boolean> extends JwtEsVerifierBase<SpecificVerifyProperties, IssuerConfig, MultiIssuer> {
    /**
     * Create an ES JWT verifier for a single issuer
     *
     * @param verifyProperties The verification properties for your issuer
     * @param additionalProperties Additional properties
     * @param additionalProperties.jwksCache Overriding JWKS cache that you want to use
     * @returns An ES JWT Verifier instance, that you can use to verify JWTs with
     */
    static create<T extends JwtEsVerifierProperties<VerifyProperties>>(verifyProperties: T & Partial<JwtEsVerifierProperties<VerifyProperties>>, additionalProperties?: {
        jwksCache: JwksCache;
    }): JwtEsVerifierSingleIssuer<T>;
    /**
     * Create an ES JWT verifier for multiple issuer
     *
     * @param verifyProperties An array of verification properties, one for each issuer
     * @param additionalProperties Additional properties
     * @param additionalProperties.jwksCache Overriding JWKS cache that you want to use
     * @returns An ES JWT Verifier instance, that you can use to verify JWTs with
     */
    static create<T extends JwtEsVerifierMultiProperties<VerifyProperties>>(verifyProperties: (T & Partial<JwtEsVerifierProperties<VerifyProperties>>)[], additionalProperties?: {
        jwksCache: JwksCache;
    }): JwtEsVerifierMultiIssuer<T>;
}
/**
 * Type for a generic key object, at runtime either the Node.js or WebCrypto concrete key object is used
 */
type GenericKeyObject = Object;
/**
 * Transform (synchronously) the JWK into an ES public key in crypto native key object format
 *
 * @param jwk: the JWK
 * @param jwtHeaderAlg: the alg from the JWT header (used if absent on JWK)
 * @param issuer: the issuer that uses the JWK for signing JWTs (may be used for caching the transformation)
 * @returns the ES public key in crypto native key object format
 */
export type JwkToKeyObjectTransformerSync = (jwk: EsSignatureJwk, jwtHeaderAlg?: SupportedSignatureAlgorithm, issuer?: string) => GenericKeyObject;
/**
 * Transform (asynchronously) the JWK into an ES public key in crypto native key object format
 *
 * @param jwk: the JWK
 * @param jwtHeaderAlg: the alg from the JWT header (used if absent on JWK)
 * @param issuer: the issuer that uses the JWK for signing JWTs (may be used for caching the transformation)
 * @returns Promise that will resolve with the ES public key in crypto native key object format
 */
export type JwkToKeyObjectTransformerAsync = AsAsync<JwkToKeyObjectTransformerSync>;
/**
 * Class representing a cache of ES public keys in native key object format
 *
 * Because it takes a bit of compute time to turn a JWK into native key object format,
 * we want to cache this computation.
 */
export declare class KeyObjectCache {
    transformJwkToKeyObjectSyncFn: JwkToKeyObjectTransformerSync;
    transformJwkToKeyObjectAsyncFn: JwkToKeyObjectTransformerAsync;
    private publicKeys;
    constructor(transformJwkToKeyObjectSyncFn?: JwkToKeyObjectTransformerSync, transformJwkToKeyObjectAsyncFn?: JwkToKeyObjectTransformerAsync);
    /**
     * Transform the JWK into an ES public key in native key object format.
     * If the transformed JWK is already in the cache, it is returned from the cache instead.
     *
     * @param jwk: the JWK
     * @param jwtHeaderAlg: the alg from the JWT header (used if absent on JWK)
     * @param issuer: the issuer that uses the JWK for signing JWTs (used for caching the transformation)
     * @returns the ES public key in native key object format
     */
    transformJwkToKeyObjectSync(jwk: EsSignatureJwk, jwtHeaderAlg?: SupportedSignatureAlgorithm, issuer?: string): GenericKeyObject;
    /**
     * Transform the JWK into an ES public key in native key object format (async).
     * If the transformed JWK is already in the cache, it is returned from the cache instead.
     *
     * @param jwk: the JWK
     * @param jwtHeaderAlg: the alg from the JWT header (used if absent on JWK)
     * @param issuer: the issuer that uses the JWK for signing JWTs (used for caching the transformation)
     * @returns the ES public key in native key object format
     */
    transformJwkToKeyObjectAsync(jwk: EsSignatureJwk, jwtHeaderAlg?: SupportedSignatureAlgorithm, issuer?: string): Promise<GenericKeyObject>;
    private putKeyObjectInCache;
    clearCache(issuer: Issuer): void;
}
export {};
