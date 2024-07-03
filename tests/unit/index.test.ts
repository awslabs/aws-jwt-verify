import {
  CognitoJwtVerifier,
  JwtVerifier,
  JwtRsaVerifier,
} from "../../src/index";

describe("unit tests index", () => {
  test("import from index works", () => {
    CognitoJwtVerifier.create({
      userPoolId: "us-east-1_abcdefg",
    });
    JwtVerifier.create({
      issuer: "https://example.com",
      jwksUri: "https://example.com/.well-known/keys.json",
    });
    JwtRsaVerifier.create({
      issuer: "https://example.com",
      jwksUri: "https://example.com/.well-known/keys.json",
    });
  });
});
