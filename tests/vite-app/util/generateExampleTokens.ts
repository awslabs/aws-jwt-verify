/* eslint-disable security/detect-non-literal-fs-filename */
import { generateKeyPair, signJwt } from "../../util/util";
import { randomUUID } from "crypto";
import { writeFileSync, existsSync, mkdirSync } from "fs";
import { join } from "path";

const ISSUER = "https://example.com";
const AUDIENCE = "aws-jwt-verify";
const JWKSFILE = "example-JWKS.json";
const JWKSURI = "/" + JWKSFILE;

const NOW = Math.floor(Date.now() / 1000) - 30;
const ONEDAY = 24 * 60 * 60;
const ONEYEAR = 365 * 24 * 60 * 60;

const baseTokenPayload = {
  sub: "TEST DATA",
  aud: AUDIENCE,
  iat: NOW,
  iss: ISSUER,
};

const validTokenPayload = {
  ...baseTokenPayload,
  nbf: NOW,
  exp: NOW + ONEYEAR,
  jti: randomUUID(),
  testcase: "valid token",
  hēłłœ: "wørłd",
};

const expiredTokenPayload = {
  ...baseTokenPayload,
  nbf: NOW - ONEDAY,
  exp: NOW,
  jti: randomUUID(),
  testcase: "expired token",
};

const notYetValidTokenPayload = {
  ...baseTokenPayload,
  nbf: NOW + 366 * 24 * 60 * 60,
  exp: Math.floor(Date.now() / 1000) + 366 * 24 * 60 * 60,
  jti: randomUUID(),
  testcase: "not yet valid token",
};

const saveFile = (
  directory: string,
  filename: string,
  contents: Record<string, unknown>
) => {
  const fullDir = join(__dirname, "..", directory);
  if (!existsSync(fullDir)) {
    mkdirSync(fullDir, { recursive: true });
  }
  const fullPath = join(fullDir, filename);
  console.log(`writing ${fullPath}...`);
  // eslint-disable-next-line security/detect-non-literal-fs-filename
  writeFileSync(fullPath, JSON.stringify(contents, null, 2) + "\n");
};

const tokendata = {
  ISSUER: "",
  AUDIENCE: "",
  JWKSURI: "",
  VALID_TOKEN: "",
  EXPIRED_TOKEN: "",
  NOT_YET_VALID_TOKEN: "",
  VALID_TOKEN_FOR_JWK_WITHOUT_ALG: "",
  VALID_TOKEN_ES256: "",
  VALID_TOKEN_ES256_PADDED: "",
  VALID_TOKEN_ES512: "",
  VALID_TOKEN_Ed25519: "",
  VALID_TOKEN_Ed448: "",
};

const main = async () => {
  const { privateKey, jwk } = generateKeyPair({
    kty: "RSA",
    kid: randomUUID(),
  });
  const { privateKey: privateKeyForJwkWithoutAlg, jwk: jwkWithoutAlg } =
    generateKeyPair({ kty: "RSA", kid: randomUUID() });
  delete jwkWithoutAlg.alg;
  const { privateKey: privateKeyEs256, jwk: jwkEs256 } = generateKeyPair({
    kty: "EC",
    kid: randomUUID(),
    alg: "ES256",
  });
  const { privateKey: privateKeyEs512, jwk: jwkEs512 } = generateKeyPair({
    kty: "EC",
    kid: randomUUID(),
    alg: "ES512",
  });
  const { privateKey: privateKeyEd25519, jwk: jwkEd25519 } = generateKeyPair({
    kty: "OKP",
    kid: randomUUID(),
    alg: "EdDSA",
    crv: "Ed25519",
  });
  const { privateKey: privateKeyEd448, jwk: jwkEd448 } = generateKeyPair({
    kty: "OKP",
    kid: randomUUID(),
    alg: "EdDSA",
    crv: "Ed448",
  });

  const jwks = {
    keys: [jwk, jwkWithoutAlg, jwkEs256, jwkEs512, jwkEd25519, jwkEd448],
  };

  const jwtHeader = { kid: jwk.kid, alg: "RS256" };
  const jwtHeaderForJwkWithoutAlg = { kid: jwkWithoutAlg.kid, alg: "RS256" };
  const jwtHeaderEs256 = { kid: jwkEs256.kid, alg: "ES256" };
  const jwtHeaderEs512 = { kid: jwkEs512.kid, alg: "ES512" };
  const jwtHeaderEd25519 = { kid: jwkEd25519.kid, alg: "EdDSA" };
  const jwtHeaderEd448 = { kid: jwkEd448.kid, alg: "EdDSA" };

  saveFile("public", JWKSFILE, jwks);
  saveFile(join("cypress", "fixtures"), JWKSFILE, jwks);

  tokendata.ISSUER = ISSUER;
  tokendata.AUDIENCE = AUDIENCE;
  tokendata.JWKSURI = JWKSURI;

  tokendata.VALID_TOKEN = signJwt(jwtHeader, validTokenPayload, privateKey);
  tokendata.VALID_TOKEN_FOR_JWK_WITHOUT_ALG = signJwt(
    jwtHeaderForJwkWithoutAlg,
    validTokenPayload,
    privateKeyForJwkWithoutAlg
  );
  tokendata.VALID_TOKEN_ES256 = signJwt(
    jwtHeaderEs256,
    validTokenPayload,
    privateKeyEs256
  );
  tokendata.VALID_TOKEN_ES256_PADDED = signJwt(
    jwtHeaderEs256,
    validTokenPayload,
    privateKeyEs256,
    { addBogusPadding: true }
  );
  tokendata.VALID_TOKEN_ES512 = signJwt(
    jwtHeaderEs512,
    validTokenPayload,
    privateKeyEs512
  );
  tokendata.EXPIRED_TOKEN = signJwt(jwtHeader, expiredTokenPayload, privateKey);
  tokendata.NOT_YET_VALID_TOKEN = signJwt(
    jwtHeader,
    notYetValidTokenPayload,
    privateKey
  );
  tokendata.VALID_TOKEN_Ed25519 = signJwt(
    jwtHeaderEd25519,
    validTokenPayload,
    privateKeyEd25519
  );
  tokendata.VALID_TOKEN_Ed448 = signJwt(
    jwtHeaderEd448,
    validTokenPayload,
    privateKeyEd448
  );

  saveFile(join("cypress", "fixtures"), "example-token-data.json", tokendata);

  console.log("done");
};

main();
