import { generateKeyPair, signJwt } from "../../util/util";
import { deconstructPublicKeyInDerFormat } from "aws-jwt-verify/asn1";
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
};

const main = async () => {
  const { privateKey, jwk, jwks } = generateKeyPair(
    deconstructPublicKeyInDerFormat,
    { kid: randomUUID() }
  );
  const jwtHeader = { kid: jwk.kid, alg: "RS256" };

  saveFile("public", JWKSFILE, jwks);
  saveFile(join("cypress", "fixtures"), JWKSFILE, jwks);

  tokendata.ISSUER = ISSUER;
  tokendata.AUDIENCE = AUDIENCE;
  tokendata.JWKSURI = JWKSURI;

  tokendata.VALID_TOKEN = signJwt(jwtHeader, validTokenPayload, privateKey);
  tokendata.EXPIRED_TOKEN = signJwt(jwtHeader, expiredTokenPayload, privateKey);
  tokendata.NOT_YET_VALID_TOKEN = signJwt(
    jwtHeader,
    notYetValidTokenPayload,
    privateKey
  );

  saveFile(join("cypress", "fixtures"), "token-data.json", tokendata);

  console.log("done");
};

main();
