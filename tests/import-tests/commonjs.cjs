const { JwtRsaVerifier } = require("aws-jwt-verify");
const awsJwtModule = require("aws-jwt-verify");
const https = require("aws-jwt-verify/https");
const { assertStringEquals } = require("aws-jwt-verify/assert");
require("aws-jwt-verify/asn1");
require("aws-jwt-verify/cognito-verifier");
require("aws-jwt-verify/jwk");
require("aws-jwt-verify/jwt-model");
require("aws-jwt-verify/jwt-rsa");
require("aws-jwt-verify/jwt");
require("aws-jwt-verify/safe-json-parse");

JwtRsaVerifier.create({
  jwksUri: "https://example.com/keys/jwks.json",
  issuer: "https://example.com/",
});

awsJwtModule.JwtRsaVerifier.create({
  jwksUri: "https://example.com/keys/jwks.json",
  issuer: "https://example.com/",
});

if (typeof https.fetchJson !== "function") {
  process.exit(1);
}

assertStringEquals("test foo", "foo", "foo");
console.log("CommonJS import succeeded!");
