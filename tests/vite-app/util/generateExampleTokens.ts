import {
  generateKeyPair,
  signJwt,
  base64url,
} from "../../installation-and-basic-usage/test-util";
import { v4 } from "uuid";
import { writeFileSync } from "fs";
import {} from "aws-jwt-verify";

const ISSUER = "https://example.com";
const AUDIENCE = "aws-jwt-verify";
const JWKSURI = "/example-JWKS.json";

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
  jti: v4(),
  testcase: "valid token",
};

const expiredTokenPayload = {
  ...baseTokenPayload,
  nbf: NOW - ONEDAY,
  exp: NOW,
  jti: v4(),
  testcase: "expired token",
};

const notYetValidTokenPayload = {
  ...baseTokenPayload,
  nbf: NOW + 366 * 24 * 60 * 60,
  exp: Math.floor(Date.now() / 1000) + 366 * 24 * 60 * 60,
  jti: v4(),
  testcase: "not yet valid token",
};

const saveFile = (filename, contents) => {
  console.log(`writing ${filename}...`);
  // eslint-disable-next-line security/detect-non-literal-fs-filename
  writeFileSync(filename, JSON.stringify(contents, null, 2) + "\n");
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
  const { privateKey, jwk } = generateKeyPair();
  jwk.kid = v4();
  const jwtHeader = { kid: jwk.kid, alg: "RS256" };

  // fix: The JWK "n" member contained a leading zero.
  // https://bugs.chromium.org/p/chromium/issues/detail?id=383998#c6
  let nBuffer = Buffer.from(jwk.n, "base64");
  if (nBuffer[0] === 0x00) {
    nBuffer = nBuffer.subarray(1);
  }
  // fix: The JWK member "n" could not be base64url decoded or contained padding
  const jwkWeb = { ...jwk, n: base64url(nBuffer) };
  const jwks = { keys: [jwkWeb] };

  saveFile("public" + JWKSURI, jwks);
  saveFile("cypress/fixtures" + JWKSURI, jwks);

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

  saveFile("cypress/fixtures/token-data.json", tokendata);

  console.log("done");
};

main();
