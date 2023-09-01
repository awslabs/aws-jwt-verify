/**
 * Utility functions used by unit and integration tests
 */

import { createSign, generateKeyPairSync, KeyObject } from "crypto";
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
  options: { kty: "RSA" } | { kty: "EC", namedCurve: "P-256" | "P-384" | "P-521"} =  { kty: "RSA" }
): KeyPair {
  const { privateKey, publicKey } = options.kty === "RSA" ? generateKeyPairSync("rsa", {
    modulusLength: 4096,
    publicExponent: 0x10001,
  }) : generateKeyPairSync("ec", {
    namedCurve: options.namedCurve
  });
  
  const jwk = publicKey.export({
    format: "jwk"
  }) as Jwk;
  jwk.use = "sig";

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
enum JwtSignatureAlgorithms {
  RS256 = "RSA-SHA256",
  RS384 = "RSA-SHA384",
  RS512 = "RSA-SHA512",
  ES256 = "RSA-SHA256",
  ES384 = "RSA-SHA384",
  ES512 = "RSA-SHA512",
}

export function signJwt(
  header: { kid?: string; alg?: string; [key: string]: any },
  payload: { [key: string]: any },
  privateKey: KeyObject,
  produceValidSignature = true
) {
  header = {
    ...header,
    alg: Object.keys(header).includes("alg") ? header.alg : "RS256",
  };
  payload = { exp: Math.floor(Date.now() / 1000 + 100), ...payload };
  const toSign = [
    Buffer.from(JSON.stringify(header)).toString("base64url"),
    Buffer.from(JSON.stringify(payload)).toString("base64url")
  ].join(".");
  const digestFunction = JwtSignatureAlgorithms[header.alg as keyof typeof JwtSignatureAlgorithms ?? "RS256"];
  const sign = createSign(
    digestFunction
  );
  sign.write(toSign);
  sign.end();
  const signature = sign.sign(privateKey);
  if (!produceValidSignature) {
    signature[0] = ~signature[0]; // swap first byte
  }
  const signedJwt = [toSign, Buffer.from(signature).toString("base64url")].join(".");
  return signedJwt;
}
