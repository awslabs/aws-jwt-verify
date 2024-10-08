import { JwtVerifier, CognitoJwtVerifier } from "aws-jwt-verify";
import * as awsJwtModule from "aws-jwt-verify";
import * as https from "aws-jwt-verify/https";
import { assertStringEquals } from "aws-jwt-verify/assert";
import {} from "aws-jwt-verify/jwk";
import {} from "aws-jwt-verify/jwt-model";
import {} from "aws-jwt-verify/jwt-verifier";
import {} from "aws-jwt-verify/jwt";
import {} from "aws-jwt-verify/safe-json-parse";
import { JwtInvalidIssuerError } from "aws-jwt-verify/error";
import {
  CognitoJwtVerifierMultiUserPool,
  CognitoJwtVerifierSingleUserPool,
  CognitoVerifyProperties as _CognitoVerifyProperties,
  CognitoJwtVerifierMultiProperties,
  CognitoJwtVerifierProperties,
  CognitoJwtVerifier as _CognitoJwtVerifier,
} from "aws-jwt-verify/cognito-verifier";

JwtVerifier.create({
  jwksUri: "https://example.com/keys/jwks.json",
  issuer: "https://example.com/",
});

awsJwtModule.JwtVerifier.create({
  jwksUri: "https://example.com/keys/jwks.json",
  issuer: "https://example.com/",
});

if (typeof https.fetch !== "function") {
  console.error("TypeScript import: https.fetch is not a function");
  process.exit(1);
}

let verifier: CognitoJwtVerifierSingleUserPool<{
  userPoolId: string;
  tokenUse: "id";
}>;
const verifyProps = {
  tokenUse: "id" as const,
};
verifyProps as CognitoJwtVerifierProperties; // cast should work
const verifierParams = {
  userPoolId: "eu-west-1_abcdefgh",
  ...verifyProps,
};
if (process.env.JUST_CHECKING_IF_THE_BELOW_TS_COMPILES_DONT_NEED_TO_RUN_IT) {
  verifier = CognitoJwtVerifier.create(verifierParams);
  verifier.verifySync("ey...", {
    clientId: "abc",
  });
}

if (process.env.JUST_CHECKING_IF_THE_BELOW_TS_COMPILES_DONT_NEED_TO_RUN_IT) {
  const otherVerifier = CognitoJwtVerifier.create({
    userPoolId: "",
    clientId: "",
  });
  otherVerifier.verifySync("", {
    tokenUse: "id",
  });
}

let multiVerifier: CognitoJwtVerifierMultiUserPool<{
  userPoolId: string;
  tokenUse: "access";
  clientId: string;
}>;
const multiVerifyProps = {
  clientId: "xyz",
  tokenUse: "access" as const,
};
multiVerifyProps as CognitoJwtVerifierMultiProperties; // cast should work
const multiVerifierParams = {
  userPoolId: "eu-west-1_abcdefgh",
  ...multiVerifyProps,
};
if (process.env.JUST_CHECKING_IF_THE_BELOW_TS_COMPILES_DONT_NEED_TO_RUN_IT) {
  multiVerifier = CognitoJwtVerifier.create(multiVerifierParams);
  multiVerifier.verifySync("ey...");
}

assertStringEquals("test foo", "foo", "foo", JwtInvalidIssuerError);
console.log("TypeScript import succeeded!");
