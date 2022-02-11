/* istanbul ignore file */

import { createSign, generateKeyPairSync, KeyObject } from "crypto";
import nock from "nock";
import { URL } from "url";
import { deconstructPublicKeyInDerFormat } from "../../src/asn1";
import { Jwk, Jwks } from "../../src/jwk";
import { JwtSignatureAlgorithms } from "../../src/jwt-rsa";

export function disallowAllRealNetworkTraffic() {
  nock.disableNetConnect();
}

export function allowAllRealNetworkTraffic() {
  nock.enableNetConnect();
}

export function generateKeyPair(options?: { kid?: string; alg?: string }) {
  const { privateKey, publicKey } = generateKeyPairSync("rsa", {
    modulusLength: 4096,
    publicExponent: 0x10001,
  });
  const jwk = publicKeyToJwk(publicKey, {
    kid: options?.kid,
    alg: options?.alg,
  });

  return {
    publicKey,
    publicKeyDer: publicKey.export({ format: "der", type: "spki" }),
    publicKeyPem: publicKey.export({ format: "pem", type: "spki" }),
    privateKey,
    privateKeyDer: privateKey.export({ format: "der", type: "pkcs8" }),
    privateKeyPem: privateKey.export({ format: "pem", type: "pkcs8" }),
    jwks: { keys: [jwk] } as Jwks,
    jwk,
    nBuffer: Buffer.from(jwk.n, "base64"),
    eBuffer: Buffer.from(jwk.e, "base64"),
  };
}

export function publicKeyToJwk(
  publicKey: KeyObject,
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
  return {
    ...jwkOptions,
    n: Buffer.from(n).toString("base64"),
    e: Buffer.from(e).toString("base64"),
  } as Jwk;
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
  if (typeof x === "string") {
    x = Buffer.from(x);
  }
  return x
    .toString("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

export function throwOnUnusedMocks() {
  if (nock.activeMocks().length) {
    throw new Error(
      `HTTP mocks still active: ${nock.activeMocks().join(", ")}`
    );
  }
}

export function mockHttpsUri(
  uri: string,
  propsOrError:
    | {
        responseStatus?: number;
        responseHeaders?: { [key: string]: string };
        responsePayload?: string | Buffer | Uint8Array;
        delayBody?: number;
      }
    | Error
) {
  const url = new URL(uri);
  const scope = nock(`https://${url.host}`).get(`${url.pathname}${url.search}`);
  if (propsOrError instanceof Error) {
    scope.replyWithError(propsOrError);
  } else {
    const defaults = {
      responseStatus: 200,
      responseHeaders: {
        "Content-Type": "application/json",
        "Content-Length": propsOrError?.responsePayload
          ? propsOrError.responsePayload.length.toString()
          : "0",
      },
    };
    propsOrError = { ...defaults, ...propsOrError };
    if (propsOrError.delayBody) {
      scope.delayBody(propsOrError.delayBody);
    }
    scope.reply(
      propsOrError.responseStatus,
      propsOrError.responsePayload,
      propsOrError.responseHeaders
    );
  }
  return scope;
}
