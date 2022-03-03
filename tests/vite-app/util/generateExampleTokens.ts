import { JWK, JWS } from "node-jose"; // https://github.com/cisco/node-jose
import { v4 } from "uuid";
import { writeFileSync } from "fs";

const keystore = (JWK as any).createKeyStore();
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

const createSign = async (jwk, payload) => {
  return await JWS.createSign(
    {
      alg: "RS256",
      format: "compact",
    },
    jwk
  )
    .update(JSON.stringify(payload), "utf8")
    .final();
};

const props = {
  alg: "RS256",
  use: "sig",
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
  const jwk = await keystore.generate("RSA", 2048, props);

  saveFile("public" + JWKSURI, keystore.toJSON());
  saveFile("cypress/fixtures" + JWKSURI, keystore.toJSON());

  tokendata.ISSUER = ISSUER;
  tokendata.AUDIENCE = AUDIENCE;
  tokendata.JWKSURI = JWKSURI;

  tokendata.VALID_TOKEN = await createSign(jwk, validTokenPayload);
  tokendata.EXPIRED_TOKEN = await createSign(jwk, expiredTokenPayload);
  tokendata.NOT_YET_VALID_TOKEN = await createSign(
    jwk,
    notYetValidTokenPayload
  );

  saveFile("cypress/fixtures/token-data.json", tokendata);

  console.log("done");
};

main();
