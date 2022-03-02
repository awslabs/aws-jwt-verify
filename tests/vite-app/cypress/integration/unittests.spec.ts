/// <reference types="cypress" />
import { JwtRsaVerifier } from "aws-jwt-verify";
import {
  VAILD_TOKEN,
  ISSUER,
  AUDIENCE,
  JWKSURI,
} from "../fixtures/token-data.json";

describe("unit tests", () => {
  it("expect true", () => {
    expect(true).to.be.true;
  });

  it("JwtRsaVerifier create & verify", async () => {
    cy.intercept("GET", JWKSURI, { fixture: "example-JWKS" });

    const verifier = JwtRsaVerifier.create({
      issuer: ISSUER,
      audience: AUDIENCE,
      jwksUri: JWKSURI,
    });

    try {
      const payload = await verifier.verify(VAILD_TOKEN);
      console.log("Token is valid. Payload:", payload);

      expect(payload).to.exist;
    } catch (ex) {
      console.log(ex);
      console.log("Token not valid!");

      expect(ex).to.be.null;
    }
  });
});
