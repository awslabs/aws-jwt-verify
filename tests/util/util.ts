/**
 * Utility functions used by unit and integration tests
 */

import { createSign, generateKeyPairSync, KeyObject } from "crypto";

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
  jwks: { keys: [ReturnType<typeof publicKeyToJwk>] };
  /** The public key of the keypair, in JWK format */
  jwk: ReturnType<typeof publicKeyToJwk>;
  /** The modulus of the public key of the keypair, as NodeJS buffer */
  nBuffer: Buffer;
  /** The exponent of the public key of the keypair, as NodeJS buffer */
  eBuffer: Buffer;
}

export function generateKeyPair(
  deconstructPublicKeyInDerFormat: (publicKey: Buffer) => {
    n: Buffer;
    e: Buffer;
  },
  options?: { kid?: string; alg?: string }
): KeyPair {
  const { privateKey, publicKey } = generateKeyPairSync("rsa", {
    modulusLength: 4096,
    publicExponent: 0x10001,
  });
  const jwk = publicKeyToJwk(publicKey, deconstructPublicKeyInDerFormat, {
    kid: options?.kid,
    alg: options?.alg,
  });

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
    nBuffer: Buffer.from(jwk.n, "base64"),
    eBuffer: Buffer.from(jwk.e, "base64"),
  };
}

export function publicKeyToJwk(
  publicKey: KeyObject,
  deconstructPublicKeyInDerFormat: (k: Buffer) => { n: Buffer; e: Buffer },
  jwkOptions: { kid?: string; alg?: string; kty?: string; use?: string } = {}
) {
  jwkOptions = {
    kid: jwkOptions.kid ?? "testkid",
    alg: jwkOptions.alg ?? "RS256",
    kty: jwkOptions.kty ?? "RSA",
    use: jwkOptions.use ?? "sig",
  };
  const { n, e } = deconstructPublicKeyInDerFormat(
    publicKey.export({ format: "der", type: "spki" })
  );
  const res = {
    ...(jwkOptions as Required<typeof jwkOptions>),
    n: base64url(removeLeadingZero(n)),
    e: base64url(removeLeadingZero(e)),
  };
  return res as {
    kid: string;
    alg?: string;
    kty: string;
    use: string;
    n: string;
    e: string;
    [key: string]: any;
  };
}

function removeLeadingZero(positiveInteger: Buffer) {
  return positiveInteger[0] === 0
    ? positiveInteger.subarray(1)
    : positiveInteger;
}

enum JwtSignatureAlgorithms {
  RS256 = "RSA-SHA256",
  RS384 = "RSA-SHA384",
  RS512 = "RSA-SHA512",
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
    base64url(JSON.stringify(header)),
    base64url(JSON.stringify(payload)),
  ].join(".");
  const sign = createSign(
    JwtSignatureAlgorithms[header.alg as keyof typeof JwtSignatureAlgorithms] ??
      "RSA-SHA256"
  );
  sign.write(toSign);
  sign.end();
  const signature = sign.sign(privateKey);
  if (!produceValidSignature) {
    signature[0] = ~signature[0]; // swap first byte
  }
  const signedJwt = [toSign, base64url(signature)].join(".");
  return signedJwt;
}

export function base64url(x: string | Buffer) {
  // Note: since Node.js 14.18 you can just do Buffer.from(x).toString("base64url")
  // That's pretty recent still, and CI environments might run older Node14, so we'll do it ourselves for a while longer
  if (typeof x === "string") {
    x = Buffer.from(x);
  }
  return x
    .toString("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}
