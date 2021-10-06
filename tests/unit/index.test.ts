import { CognitoJwtVerifier, JwtRsaVerifier } from "../../src/index";

describe("import from index works", () => {
  test("import from index works", () => {
    CognitoJwtVerifier.create({
      userPoolId: "us-east-1_abcdefg",
    });
    JwtRsaVerifier.create({
      issuer: "https://example.com",
      jwksUri: "https://example.com/.well-known/keys.json",
    });
  });
});
