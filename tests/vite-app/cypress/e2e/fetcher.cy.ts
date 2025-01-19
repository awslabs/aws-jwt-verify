/// <reference types="cypress" />
import { SimpleFetcher } from "aws-jwt-verify/https";

describe("Fetcher", () => {
  let tokenData;

  beforeEach(() => {
    cy.fixture("example-token-data.json").then((data) => {
      tokenData = data;
    });
  });

  it("Simple JSON fetcher works", () => {
    cy.visit("/");

    cy.fixture("example-JWKS.json").then((jwksData) => {
      const fetcher = new SimpleFetcher();

      fetcher.fetch(tokenData.JWKSURI).then((jwks) => {
        expect(jwks).to.deep.equal(jwksData);
      });
    });
  });
});
