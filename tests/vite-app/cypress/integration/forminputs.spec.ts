/// <reference types="cypress" />
import { ISSUER, AUDIENCE, JWKSURI, VAILD_TOKEN, EXPIRED_TOKEN, NOT_YET_VALID_TOKEN } from '../fixtures/token-data.json';

describe('enable Verify RSA', () => {
  it('enables the "Verify RSA" button', () => {
    cy.visit('/');

    cy.get('#verifyrsa').should('be.disabled');
    cy.get('#result').should('have.text', 'Unverified');

    cy.get('#jwt').type('JWT');
    cy.get('#verifyrsa').should('not.be.disabled');
  });
});

describe('click Verify RSA', () => {
  const INVAILD_ISSUER = 'https://example.org';
  const INVAILD_JWKSURI = '/notexample-JWKS.json';

  beforeEach(() => {
    cy.visit('/');
  });

  const typeInputsAndClick = (jwt, issuer = '', audience= '', jwksuri = '') => {
    cy.get('#jwt').type(jwt, {delay: 0});
    if (issuer) {
      cy.get('#issuer').type(issuer);
    }
    if (audience) {
      cy.get('#audience').type(audience);
    }
    if (jwksuri) {
      cy.get('#jwksuri').type(jwksuri);
    }

    cy.get('#verifyrsa').click();    
  };

  it('valid token', () => {
    typeInputsAndClick(VAILD_TOKEN, ISSUER, AUDIENCE, JWKSURI);

    cy.get('#result').should('have.text', 'Verified');
  });

  it('expired token', () => {
    typeInputsAndClick(EXPIRED_TOKEN, ISSUER, AUDIENCE, JWKSURI);

    cy.get('#result').should('include.text', 'Token expired at ');
  });

  it('not yet valid token', () => {
    typeInputsAndClick(NOT_YET_VALID_TOKEN, ISSUER, AUDIENCE, JWKSURI);

    cy.get('#result').should('include.text', 'Token can\'t be used before ');
  });

  it('invalid issuer', () => {
    typeInputsAndClick(VAILD_TOKEN, INVAILD_ISSUER, '', JWKSURI);

    cy.get('#result').should('include.text', 'Issuer not allowed');
  });

  it('invalid JWKS Uri', () => {
    typeInputsAndClick(VAILD_TOKEN, ISSUER, '', INVAILD_JWKSURI);

    // npm run dev & http://localhost:3000/'
    //   Unexpected token < in JSON at position 0
    // npm run preview & http://localhost:4173/'
    //   Unexpected end of JSON input
    cy.get('#result').should('include.text', 'Unexpected');
    cy.get('#result').should('include.text', 'JSON');

  }); 

});