import { JwtRsaVerifier } from "aws-jwt-verify";
import * as awsJwtModule from "aws-jwt-verify";
import * as https from "aws-jwt-verify/https";
import { assertStringEquals } from "aws-jwt-verify/assert";
import {} from "aws-jwt-verify/asn1";
import {} from "aws-jwt-verify/cognito-verifier";
import {} from "aws-jwt-verify/jwk";
import {} from "aws-jwt-verify/jwt-model";
import {} from "aws-jwt-verify/jwt-rsa";
import {} from "aws-jwt-verify/jwt";
import {} from "aws-jwt-verify/safe-json-parse";

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
console.log("TypeScript import succeeded!");
