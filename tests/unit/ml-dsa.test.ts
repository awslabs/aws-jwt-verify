import { generateKeyPairSync, sign } from "crypto";
import {
  MlDsaAlgorithm,
  Jwk,
  JwkWithKid,
  assertIsSignatureJwk,
  mlDsaAlgorithms,
} from "../../src/jwk";
import { decomposeUnverifiedJwt } from "../../src/jwt";
import { nodeWebCompat as webCryptoCompat } from "../../src/node-web-compat-web";
import { verifyJwt, verifyJwtSync } from "../../src/jwt-verifier";
import {
  JwtInvalidSignatureAlgorithmError,
  JwtInvalidSignatureError,
} from "../../src/error";

function generateMlDsaKeyPair(alg: MlDsaAlgorithm) {
  return generateKeyPairSync(alg.toLowerCase() as never);
}

const mlDsaAvailable = (() => {
  try {
    generateMlDsaKeyPair("ML-DSA-44");
    return true;
  } catch {
    return false;
  }
})();

function createMlDsaJwt(
  alg: MlDsaAlgorithm,
  privateKey: ReturnType<typeof generateMlDsaKeyPair>["privateKey"],
  options?: { headerAlg?: MlDsaAlgorithm; invalidSignature?: boolean }
) {
  const header = Buffer.from(
    JSON.stringify({ alg: options?.headerAlg ?? alg, kid: "testkid" })
  ).toString("base64url");
  const payload = Buffer.from(
    JSON.stringify({
      iss: "https://example.com",
      aud: "audience",
      exp: Math.floor(Date.now() / 1000) + 60,
    })
  ).toString("base64url");
  const signingInput = `${header}.${payload}`;
  const signature = sign(null, Buffer.from(signingInput), privateKey);
  if (options?.invalidSignature) {
    signature[0] ^= 1;
  }
  return `${signingInput}.${signature.toString("base64url")}`;
}

(mlDsaAvailable ? describe : describe.skip)(
  "unit tests RFC 9964 ML-DSA",
  () => {
    test.each(mlDsaAlgorithms)("verifies %s synchronously", (alg) => {
      const { privateKey, publicKey } = generateMlDsaKeyPair(alg);
      const jwk = publicKey.export({ format: "jwk" }) as Jwk;
      Object.assign(jwk, { alg, kid: "testkid", use: "sig" });
      const jwt = createMlDsaJwt(alg, privateKey);

      expect(
        verifyJwtSync(jwt, jwk, {
          issuer: "https://example.com",
          audience: "audience",
        })
      ).toMatchObject({ iss: "https://example.com", aud: "audience" });
    });

    test("verifies asynchronously", async () => {
      const alg = "ML-DSA-44";
      const { privateKey, publicKey } = generateMlDsaKeyPair(alg);
      const jwk = publicKey.export({ format: "jwk" }) as JwkWithKid;
      Object.assign(jwk, { alg, kid: "testkid", use: "sig" });
      const jwt = createMlDsaJwt(alg, privateKey);

      await expect(
        verifyJwt(
          jwt,
          "https://example.com/.well-known/jwks.json",
          { issuer: "https://example.com", audience: "audience" },
          async () => jwk
        )
      ).resolves.toMatchObject({
        iss: "https://example.com",
        aud: "audience",
      });
    });

    test("verifies with WebCrypto", async () => {
      const alg = "ML-DSA-44";
      const { privateKey, publicKey } = generateMlDsaKeyPair(alg);
      const jwk = publicKey.export({ format: "jwk" }) as Jwk;
      Object.assign(jwk, { alg, kid: "testkid", use: "sig" });
      assertIsSignatureJwk(jwk);
      const jwt = createMlDsaJwt(alg, privateKey);
      const { headerB64, payloadB64, signatureB64 } =
        decomposeUnverifiedJwt(jwt);
      const keyObject = await webCryptoCompat.transformJwkToKeyObjectAsync(
        jwk,
        alg
      );

      await expect(
        webCryptoCompat.verifySignatureAsync({
          alg,
          keyObject,
          jwsSigningInput: `${headerB64}.${payloadB64}`,
          signature: signatureB64,
        })
      ).resolves.toBe(true);
    });

    test("rejects an invalid signature", () => {
      const alg = "ML-DSA-44";
      const { privateKey, publicKey } = generateMlDsaKeyPair(alg);
      const jwk = publicKey.export({ format: "jwk" }) as Jwk;
      Object.assign(jwk, { alg, kid: "testkid", use: "sig" });
      const jwt = createMlDsaJwt(alg, privateKey, {
        invalidSignature: true,
      });

      expect(() =>
        verifyJwtSync(jwt, jwk, {
          issuer: "https://example.com",
          audience: "audience",
        })
      ).toThrow(JwtInvalidSignatureError);
    });

    test("rejects mismatched AKP and JWT algorithms", () => {
      const alg = "ML-DSA-44";
      const { privateKey, publicKey } = generateMlDsaKeyPair(alg);
      const jwk = publicKey.export({ format: "jwk" }) as Jwk;
      Object.assign(jwk, { alg, kid: "testkid", use: "sig" });
      const jwt = createMlDsaJwt(alg, privateKey, {
        headerAlg: "ML-DSA-65",
      });

      expect(() =>
        verifyJwtSync(jwt, jwk, {
          issuer: "https://example.com",
          audience: "audience",
        })
      ).toThrow(JwtInvalidSignatureAlgorithmError);
    });
  }
);
