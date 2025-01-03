/**
 * Utility functions used by unit and integration tests
 */

import { createSign, generateKeyPairSync, KeyObject, sign } from "crypto";
import { Jwk } from "../../src/jwk";

/** RSA keypair with its various manifestations as properties, for use in automated tests */
export interface KeyPair {
  /** The public key of the keypair, in native NodeJS key format */
  publicKey: KeyObject;
  /** The public key of the keypair, in DER format */
  publicKeyDer: Buffer;
  /** The public key of the keypair, in PEM format */
  publicKeyPem: string;
  /** The private key of the keypair, in native NodeJS key format */
  privateKey: KeyObject;
  /** The private key of the keypair, in DER format */
  privateKeyDer: Buffer;
  /** The private key of the keypair, in PEM format */
  privateKeyPem: string;
  /** The public key of the keypair, in JWK format, wrapped as a JWKS */
  jwks: { keys: Jwk[] };
  /** The public key of the keypair, in JWK format */
  jwk: Jwk;
}

export function generateKeyPair(
  options:
    | {
        kty: "RSA";
        alg?: "RS256" | "RS384" | "RS512";
        kid?: string;
        use?: string;
      }
    | {
        kty: "EC";
        alg?: "ES256" | "ES384" | "ES512";
        kid?: string;
        use?: string;
      }
    | {
        kty: "OKP";
        alg: "EdDSA";
        crv: "Ed25519" | "Ed448";
        kid?: string;
        use?: string;
      } = {
    kty: "RSA",
    alg: "RS256",
    use: "sig",
  }
): KeyPair {
  const { privateKey, publicKey } =
    options.kty === "RSA"
      ? generateKeyPairSync("rsa", {
          modulusLength: 4096,
          publicExponent: 0x10001,
        })
      : options.kty === "EC"
        ? generateKeyPairSync("ec", {
            namedCurve: { ES256: "P-256", ES384: "P-384", ES512: "P-521" }[
              options.alg ?? "ES256"
            ],
          })
        : options.crv === "Ed25519"
          ? generateKeyPairSync("ed25519")
          : generateKeyPairSync("ed448");

  const jwk = publicKey.export({
    format: "jwk",
  }) as Jwk;
  jwk.alg =
    "alg" in options
      ? options.alg
      : options.kty === "RSA"
        ? "RS256"
        : options.kty === "EC"
          ? "ES256"
          : "EdDSA";
  jwk.kid = "kid" in options ? options.kid : "testkid";
  jwk.use = "use" in options ? options.use : "sig";

  return {
    publicKey,
    publicKeyDer: publicKey.export({ format: "der", type: "spki" }),
    publicKeyPem: publicKey.export({ format: "pem", type: "spki" }) as string,
    privateKey,
    privateKeyDer: privateKey.export({ format: "der", type: "pkcs8" }),
    privateKeyPem: privateKey.export({
      format: "pem",
      type: "pkcs8",
    }) as string,
    jwks: { keys: [jwk] },
    jwk,
  };
}

/**
 * Enum to map supported JWT signature algorithms with OpenSSL message digest algorithm names
 */
enum JwtSignatureAlgorithmHashNames {
  RS256 = "RSA-SHA256",
  RS384 = "RSA-SHA384",
  RS512 = "RSA-SHA512",
  ES256 = RS256,
  ES384 = RS384,
  ES512 = RS512,
}

type JwtSignatureAlgorithm =
  | keyof typeof JwtSignatureAlgorithmHashNames
  | "EdDSA";

/**
 * Create a signed JWT with the given header and payload.
 * The signature algorithm will be taken from the "alg" in the header that you provide, and will default to RS256 if not given.
 * @param header
 * @param payload
 * @param privateKey
 * @param produceValidSignature
 * @returns
 */
export function signJwt(
  header: { kid?: string; alg?: string; [key: string]: any },
  payload: { [key: string]: any },
  privateKey: KeyObject,
  options?: {
    produceValidSignature?: boolean;
    addBogusPadding?: boolean;
  }
) {
  header = {
    ...header,
    alg: "alg" in header ? header.alg : "RS256",
  };
  payload = { exp: Math.floor(Date.now() / 1000 + 100), ...payload };
  const bogusPadding = options?.addBogusPadding ? "=" : "";
  const toSign = [
    Buffer.from(JSON.stringify(header)).toString("base64url") + bogusPadding,
    Buffer.from(JSON.stringify(payload)).toString("base64url") + bogusPadding,
  ].join(".");
  let signature: Buffer;
  const alg = (header.alg as JwtSignatureAlgorithm) ?? "RS256";
  if (alg === "EdDSA") {
    signature = sign(null, Buffer.from(toSign), privateKey);
  } else {
    // eslint-disable-next-line security/detect-object-injection
    const digestFunction = JwtSignatureAlgorithmHashNames[alg];
    const sign = createSign(digestFunction);
    sign.write(toSign);
    sign.end();
    signature = sign.sign({
      key: privateKey,
      dsaEncoding: "ieee-p1363", // Signature format r || s (not used for RSA)
    });
  }
  if (options?.produceValidSignature === false) {
    // Invert the bits of a random byte
    const index = Math.floor(Math.random() * signature.length);
    // eslint-disable-next-line security/detect-object-injection
    signature[index] = ~signature[index];
  }
  const signedJwt = [
    toSign,
    Buffer.from(signature).toString("base64url") + bogusPadding,
  ].join(".");
  return signedJwt;
}
