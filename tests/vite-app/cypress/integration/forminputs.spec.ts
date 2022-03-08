/// <reference types="cypress" />
import {
  ISSUER,
  AUDIENCE,
  JWKSURI,
  VALID_TOKEN,
  EXPIRED_TOKEN,
  NOT_YET_VALID_TOKEN,
} from "../fixtures/token-data.json";

describe("enable Verify RSA", () => {
  it('enables the "Verify RSA" button', () => {
    cy.visit("/");

    cy.get("#verifyrsa").should("be.disabled");
    cy.get("#result").should("have.text", "Unverified");

    cy.get("#jwt").type("JWT");
    cy.get("#verifyrsa").should("not.be.disabled");
  });
});

describe("click Verify RSA", () => {
  const INVAILD_ISSUER = "https://example.org";
  const INVAILD_JWKSURI = "/notexample-JWKS.json";
  const INVAILD_AUDIENCE = "notaudience";

  beforeEach(() => {
    cy.visit("/");
  });

  const typeInputsAndClick = (
    jwt,
    issuer = "",
    audience = "",
    jwksuri = ""
  ) => {
    cy.get("#jwt").type(jwt, { delay: 0 });
    if (issuer) {
      cy.get("#issuer").type(issuer, { delay: 0 });
    }
    if (audience) {
      cy.get("#audience").type(audience, { delay: 0 });
    }
    if (jwksuri) {
      cy.get("#jwksuri").type(jwksuri, { delay: 0 });
    }

    cy.get("#verifyrsa").click();
  };

  it("valid token", () => {
    typeInputsAndClick(VALID_TOKEN, ISSUER, AUDIENCE, JWKSURI);

    cy.get("#result").should("have.text", "Verified");
  });

  it("expired token", () => {
    typeInputsAndClick(EXPIRED_TOKEN, ISSUER, AUDIENCE, JWKSURI);

    cy.get("#result").should("include.text", "Token expired at ");
  });

  it("not yet valid token", () => {
    typeInputsAndClick(NOT_YET_VALID_TOKEN, ISSUER, AUDIENCE, JWKSURI);

    cy.get("#result").should("include.text", "Token can't be used before ");
  });

  it("invalid issuer", () => {
    typeInputsAndClick(VALID_TOKEN, INVAILD_ISSUER, "", JWKSURI);

    cy.get("#result").should("include.text", "Issuer not allowed");
  });

  it("invalid audience", () => {
    typeInputsAndClick(VALID_TOKEN, ISSUER, INVAILD_AUDIENCE, JWKSURI);

    cy.get("#result").should("include.text", "Audience not allowed");
  });

  it("invalid signature", () => {
    typeInputsAndClick(
      VALID_TOKEN.substring(0, VALID_TOKEN.length - 2),
      ISSUER,
      "",
      JWKSURI
    );

    cy.get("#result").should("include.text", "Invalid signature");
  });

  it("invalid JWKS Uri", () => {
    typeInputsAndClick(VALID_TOKEN, ISSUER, "", INVAILD_JWKSURI);

    cy.get("#result").should(
      "include.text",
      "Failed to fetch /notexample-JWKS.json: Status code is 404, expected 200"
    );
  });
});
