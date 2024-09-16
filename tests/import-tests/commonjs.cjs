const { JwtVerifier } = require("aws-jwt-verify");
const awsJwtModule = require("aws-jwt-verify");
const https = require("aws-jwt-verify/https");
const { assertStringEquals } = require("aws-jwt-verify/assert");
require("aws-jwt-verify/cognito-verifier");
require("aws-jwt-verify/jwk");
require("aws-jwt-verify/jwt-model");
require("aws-jwt-verify/jwt-verifier");
require("aws-jwt-verify/jwt");
require("aws-jwt-verify/safe-json-parse");
const { JwtInvalidIssuerError } = require("aws-jwt-verify/error");

JwtVerifier.create({
  jwksUri: "https://example.com/keys/jwks.json",
  issuer: "https://example.com/",
});

awsJwtModule.JwtVerifier.create({
  jwksUri: "https://example.com/keys/jwks.json",
  issuer: "https://example.com/",
});

if (typeof https.fetch !== "function") {
  console.error("CJS import: https.fetch is not a function");
  process.exit(1);
}

assertStringEquals("test foo", "foo", "foo", JwtInvalidIssuerError);
console.log("CommonJS import succeeded!");
