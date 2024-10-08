import { JwtVerifier } from "aws-jwt-verify";
import * as awsJwtModule from "aws-jwt-verify";
import * as https from "aws-jwt-verify/https";
import { assertStringEquals } from "aws-jwt-verify/assert";
import {} from "aws-jwt-verify/cognito-verifier";
import {} from "aws-jwt-verify/jwk";
import {} from "aws-jwt-verify/jwt-model";
import {} from "aws-jwt-verify/jwt-verifier";
import {} from "aws-jwt-verify/jwt";
import {} from "aws-jwt-verify/safe-json-parse";
import { JwtInvalidIssuerError } from "aws-jwt-verify/error";

JwtVerifier.create({
  jwksUri: "https://example.com/keys/jwks.json",
  issuer: "https://example.com/",
});

awsJwtModule.JwtVerifier.create({
  jwksUri: "https://example.com/keys/jwks.json",
  issuer: "https://example.com/",
});

if (typeof https.fetch !== "function") {
  console.error("ESM import: https.fetch is not a function");
  process.exit(1);
}

assertStringEquals("test foo", "foo", "foo", JwtInvalidIssuerError);
console.log("ESM import succeeded!");
