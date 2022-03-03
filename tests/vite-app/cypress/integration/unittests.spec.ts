/// <reference types="cypress" />
import { JwtRsaVerifier } from "aws-jwt-verify";
import {
  VALID_TOKEN,
  ISSUER,
  AUDIENCE,
  JWKSURI,
} from "../fixtures/token-data.json";

describe("unit tests", () => {
  it("JwtRsaVerifier create & verify", async () => {
    cy.intercept("GET", JWKSURI, { fixture: "example-JWKS" });

    const verifier = JwtRsaVerifier.create({
      issuer: ISSUER,
      audience: AUDIENCE,
      jwksUri: JWKSURI,
    });

    try {
      const payload = await verifier.verify(VALID_TOKEN);
      console.log("Token is valid. Payload:", payload);

      expect(payload).to.exist;
    } catch (ex) {
      console.log(ex);
      console.log("Token not valid!");

      expect(ex).to.be.null;
    }
  });
});
