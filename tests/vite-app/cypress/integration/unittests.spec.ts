/// <reference types="cypress" />
import { JwtRsaVerifier } from "aws-jwt-verify";
import {
  JwtExpiredError,
  JwtNotBeforeError,
  JwtInvalidIssuerError,
  JwtInvalidAudienceError,
  JwtInvalidSignatureError,
} from "aws-jwt-verify/error";
import {
  ISSUER,
  AUDIENCE,
  JWKSURI,
  VALID_TOKEN,
  EXPIRED_TOKEN,
  NOT_YET_VALID_TOKEN,
} from "../fixtures/token-data.json";

describe("unit tests", () => {
  const INVAILD_ISSUER = "https://example.org";
  const INVAILD_JWKSURI = "/notexample-JWKS.json";
  const INVAILD_AUDIENCE = "notaudience";

  beforeEach(() => {
    cy.intercept("GET", JWKSURI, { fixture: "example-JWKS" });
  });

  it("valid token", async () => {
    const verifier = JwtRsaVerifier.create({
      issuer: ISSUER,
      audience: AUDIENCE,
      jwksUri: JWKSURI,
    });
    const payload = await verifier.verify(VALID_TOKEN);

    expect(payload).to.exist;
  });

  it("expired token", async () => {
    const verifier = JwtRsaVerifier.create({
      issuer: ISSUER,
      audience: AUDIENCE,
      jwksUri: JWKSURI,
    });

    try {
      const payload = await verifier.verify(EXPIRED_TOKEN);

      expect(payload).to.not.exist;
    } catch (ex) {
      expect(ex).to.be.an.instanceof(JwtExpiredError);

      expect(ex.message).to.include("Token expired at ");
    }
  });

  it("not yet valid token", async () => {
    const verifier = JwtRsaVerifier.create({
      issuer: ISSUER,
      audience: AUDIENCE,
      jwksUri: JWKSURI,
    });

    try {
      const payload = await verifier.verify(NOT_YET_VALID_TOKEN);

      expect(payload).to.not.exist;
    } catch (ex) {
      expect(ex).to.be.an.instanceof(JwtNotBeforeError);

      expect(ex.message).to.include("Token can't be used before ");
    }
  });

  it("invalid issuer", async () => {
    const verifier = JwtRsaVerifier.create({
      issuer: INVAILD_ISSUER,
      audience: AUDIENCE,
      jwksUri: JWKSURI,
    });

    try {
      const payload = await verifier.verify(VALID_TOKEN);

      expect(payload).to.not.exist;
    } catch (ex) {
      expect(ex).to.be.an.instanceof(JwtInvalidIssuerError);

      expect(ex.message).to.include("Issuer not allowed");
    }
  });

  it("invalid audience", async () => {
    const verifier = JwtRsaVerifier.create({
      issuer: ISSUER,
      audience: INVAILD_AUDIENCE,
      jwksUri: JWKSURI,
    });

    try {
      const payload = await verifier.verify(VALID_TOKEN);

      expect(payload).to.not.exist;
    } catch (ex) {
      expect(ex).to.be.an.instanceof(JwtInvalidAudienceError);

      expect(ex.message).to.include("Audience not allowed");
    }
  });

  it("invalid signature", async () => {
    const verifier = JwtRsaVerifier.create({
      issuer: ISSUER,
      audience: AUDIENCE,
      jwksUri: JWKSURI,
    });

    try {
      const payload = await verifier.verify(
        VALID_TOKEN.substring(0, VALID_TOKEN.length - 2)
      );

      expect(payload).to.not.exist;
    } catch (ex) {
      expect(ex).to.be.an.instanceof(JwtInvalidSignatureError);

      expect(ex.message).to.include("Invalid signature");
    }
  });

  it("invalid JWKS Uri", async () => {
    const verifier = JwtRsaVerifier.create({
      issuer: ISSUER,
      audience: AUDIENCE,
      jwksUri: INVAILD_JWKSURI,
    });

    try {
      const payload = await verifier.verify(VALID_TOKEN);

      expect(payload).to.not.exist;
    } catch (ex) {
      expect(ex.message).to.include(
        "Failed to fetch /notexample-JWKS.json: Status code is 404, expected 200"
      );
    }
  });
});
