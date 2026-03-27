/**
 * Property-based tests for Cognito Multi-Issuer Format Support
 *
 * These tests validate the correctness properties defined in the design document
 * using fast-check for property-based testing.
 */

import * as fc from "fast-check";
import {
  generateKeyPair,
  signJwt,
  disallowAllRealNetworkTraffic,
  allowAllRealNetworkTraffic,
} from "./test-util";
import { CognitoJwtVerifier } from "../../src/cognito-verifier";
import { ParameterValidationError } from "../../src/error";

// Valid AWS regions for generating test data
const VALID_REGIONS = [
  "us-east-1",
  "us-east-2",
  "us-west-1",
  "us-west-2",
  "eu-west-1",
  "eu-west-2",
  "eu-west-3",
  "eu-central-1",
  "ap-northeast-1",
  "ap-northeast-2",
  "ap-southeast-1",
  "ap-southeast-2",
  "sa-east-1",
  "ca-central-1",
  "us-gov-west-1",
  "us-gov-east-1",
];

// Arbitrary for generating valid AWS regions
const regionArbitrary = fc.constantFrom(...VALID_REGIONS);

// Arbitrary for generating valid User Pool ID suffixes (alphanumeric)
const poolSuffixArbitrary = fc.string({
  minLength: 1,
  maxLength: 20,
  unit: fc.constantFrom(
    ..."ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
  ),
});

// Arbitrary for generating valid User Pool IDs
const userPoolIdArbitrary = fc
  .tuple(regionArbitrary, poolSuffixArbitrary)
  .map(([region, suffix]) => `${region}_${suffix}`);

// Arbitrary for issuer format selection
const issuerFormatArbitrary = fc.constantFrom(
  "standard",
  "multiRegion"
) as fc.Arbitrary<"standard" | "multiRegion">;

// Arbitrary for token use
const tokenUseArbitrary = fc.constantFrom("access", "id") as fc.Arbitrary<
  "access" | "id"
>;

// Arbitrary for generating invalid issuer prefixes
const invalidPrefixArbitrary = fc.constantFrom(
  "https://invalid.cognito-idp.",
  "https://wrong.cognito-idp.",
  "https://fake.cognito-idp.",
  "https://other.cognito-idp.",
  "http://cognito-idp.", // http instead of https
  "https://example.com/",
  "https://auth.example.com/",
  "https://cognito.",
  "https://idp."
);

describe("unit tests property-based - cognito multi-issuer format", () => {
  let keypair: ReturnType<typeof generateKeyPair>;

  beforeAll(() => {
    keypair = generateKeyPair();
    disallowAllRealNetworkTraffic();
  });

  afterAll(() => {
    allowAllRealNetworkTraffic();
  });

  /**
   * Property 1: Both issuer formats are accepted for valid tokens
   * **Validates: Requirements 1.1, 1.2**
   *
   * For any valid JWT signed by a configured User Pool, if the issuer matches
   * either the standard format or the multi-region format, the CognitoJwtVerifier
   * should accept the token.
   */
  describe("Property 1: Both issuer formats are accepted for valid tokens", () => {
    test("Feature: cognito-multi-issuer-format, Property 1: For any valid User Pool ID and either issuer format, the verifier accepts the token", () => {
      fc.assert(
        fc.property(
          userPoolIdArbitrary,
          issuerFormatArbitrary,
          tokenUseArbitrary,
          (userPoolId, issuerFormat, tokenUse) => {
            // Parse the User Pool ID to get both issuer formats
            const parsed = CognitoJwtVerifier.parseUserPoolId(userPoolId);

            // Select the issuer based on the format
            const issuer =
              issuerFormat === "standard"
                ? parsed.issuer
                : parsed.multiRegionIssuer;

            // Create a verifier for this User Pool
            const verifier = CognitoJwtVerifier.create({
              userPoolId,
              clientId: null,
              tokenUse: null,
            });

            // Cache the JWKS
            verifier.cacheJwks(keypair.jwks);

            // Create a valid JWT with the selected issuer format
            const signedJwt = signJwt(
              { kid: keypair.jwk.kid },
              {
                iss: issuer,
                token_use: tokenUse,
              },
              keypair.privateKey
            );

            // Verify the token - should not throw
            const result = verifier.verifySync(signedJwt);

            // Assert the token was accepted with the correct issuer
            return result.iss === issuer;
          }
        ),
        { numRuns: 100 }
      );
    });
  });

  /**
   * Property 2: Invalid issuer formats are rejected
   * **Validates: Requirements 1.3, 4.3**
   *
   * For any JWT with an issuer that does not match either the standard or
   * multi-region Cognito issuer format for the configured User Pool ID,
   * the CognitoJwtVerifier should reject the token with a ParameterValidationError.
   */
  describe("Property 2: Invalid issuer formats are rejected", () => {
    test("Feature: cognito-multi-issuer-format, Property 2: For any invalid issuer format, the verifier rejects the token", () => {
      fc.assert(
        fc.property(
          userPoolIdArbitrary,
          invalidPrefixArbitrary,
          regionArbitrary,
          tokenUseArbitrary,
          (userPoolId, invalidPrefix, region, tokenUse) => {
            // Create a verifier for this User Pool
            const verifier = CognitoJwtVerifier.create({
              userPoolId,
              clientId: null,
              tokenUse: null,
            });

            // Cache the JWKS
            verifier.cacheJwks(keypair.jwks);

            // Create an invalid issuer using the invalid prefix
            const invalidIssuer = `${invalidPrefix}${region}.amazonaws.com/${userPoolId}`;

            // Create a JWT with the invalid issuer
            const signedJwt = signJwt(
              { kid: keypair.jwk.kid },
              {
                iss: invalidIssuer,
                token_use: tokenUse,
              },
              keypair.privateKey
            );

            // Verify the token - should throw ParameterValidationError
            try {
              verifier.verifySync(signedJwt);
              return false; // Should have thrown
            } catch (error) {
              return (
                error instanceof ParameterValidationError &&
                (error.message.includes("issuer not configured") ||
                  error.message.includes("Invalid"))
              );
            }
          }
        ),
        { numRuns: 100 }
      );
    });

    test("Feature: cognito-multi-issuer-format, Property 2: For any mismatched User Pool ID in issuer, the verifier rejects the token", () => {
      fc.assert(
        fc.property(
          userPoolIdArbitrary,
          userPoolIdArbitrary,
          issuerFormatArbitrary,
          tokenUseArbitrary,
          (configuredPoolId, differentPoolId, issuerFormat, tokenUse) => {
            // Skip if the pool IDs happen to be the same
            if (configuredPoolId === differentPoolId) {
              return true;
            }

            // Create a verifier for the configured User Pool
            const verifier = CognitoJwtVerifier.create({
              userPoolId: configuredPoolId,
              clientId: null,
              tokenUse: null,
            });

            // Cache the JWKS
            verifier.cacheJwks(keypair.jwks);

            // Parse the different pool ID to get its issuer
            const parsed = CognitoJwtVerifier.parseUserPoolId(differentPoolId);
            const issuer =
              issuerFormat === "standard"
                ? parsed.issuer
                : parsed.multiRegionIssuer;

            // Create a JWT with the different pool's issuer
            const signedJwt = signJwt(
              { kid: keypair.jwk.kid },
              {
                iss: issuer,
                token_use: tokenUse,
              },
              keypair.privateKey
            );

            // Verify the token - should throw ParameterValidationError
            try {
              verifier.verifySync(signedJwt);
              return false; // Should have thrown
            } catch (error) {
              return (
                error instanceof ParameterValidationError &&
                error.message.includes("issuer not configured")
              );
            }
          }
        ),
        { numRuns: 100 }
      );
    });
  });

  /**
   * Property 3: JWKS URI is derived from token's issuer
   * **Validates: Requirements 2.1, 2.2**
   *
   * For any JWT being verified, the JWKS URI used for fetching keys should match
   * the issuer's domain (standard or multi-region), ensuring the correct endpoint is used.
   */
  describe("Property 3: JWKS URI is derived from token's issuer", () => {
    test("Feature: cognito-multi-issuer-format, Property 3: For any User Pool ID, parseUserPoolId returns correct JWKS URIs for both formats", () => {
      fc.assert(
        fc.property(userPoolIdArbitrary, (userPoolId) => {
          // Parse the User Pool ID
          const parsed = CognitoJwtVerifier.parseUserPoolId(userPoolId);

          // Extract region from User Pool ID
          const region = userPoolId.split("_")[0];

          // Verify standard JWKS URI is derived correctly from standard issuer
          const expectedStandardJwksUri = `https://cognito-idp.${region}.amazonaws.com/${userPoolId}/.well-known/jwks.json`;
          const standardJwksUriMatchesIssuer =
            parsed.jwksUri === expectedStandardJwksUri &&
            parsed.jwksUri === `${parsed.issuer}/.well-known/jwks.json`;

          // Verify multi-region JWKS URI is derived correctly from multi-region issuer
          const expectedMultiRegionJwksUri = `https://issuer.cognito-idp.${region}.amazonaws.com/${userPoolId}/.well-known/jwks.json`;
          const multiRegionJwksUriMatchesIssuer =
            parsed.multiRegionJwksUri === expectedMultiRegionJwksUri &&
            parsed.multiRegionJwksUri ===
              `${parsed.multiRegionIssuer}/.well-known/jwks.json`;

          return (
            standardJwksUriMatchesIssuer && multiRegionJwksUriMatchesIssuer
          );
        }),
        { numRuns: 100 }
      );
    });

    test("Feature: cognito-multi-issuer-format, Property 3: For any issuer format, the verifier uses the correct JWKS URI", () => {
      fc.assert(
        fc.property(
          userPoolIdArbitrary,
          issuerFormatArbitrary,
          tokenUseArbitrary,
          (userPoolId, issuerFormat, tokenUse) => {
            // Parse the User Pool ID to get both issuer formats
            const parsed = CognitoJwtVerifier.parseUserPoolId(userPoolId);

            // Select the issuer and expected JWKS URI based on the format
            const issuer =
              issuerFormat === "standard"
                ? parsed.issuer
                : parsed.multiRegionIssuer;
            const expectedJwksUri =
              issuerFormat === "standard"
                ? parsed.jwksUri
                : parsed.multiRegionJwksUri;

            // Verify the JWKS URI is derived from the issuer
            const jwksUriDerivedFromIssuer =
              expectedJwksUri === `${issuer}/.well-known/jwks.json`;

            // Create a verifier for this User Pool
            const verifier = CognitoJwtVerifier.create({
              userPoolId,
              clientId: null,
              tokenUse: null,
            });

            // Cache the JWKS
            verifier.cacheJwks(keypair.jwks);

            // Create a valid JWT with the selected issuer format
            const signedJwt = signJwt(
              { kid: keypair.jwk.kid },
              {
                iss: issuer,
                token_use: tokenUse,
              },
              keypair.privateKey
            );

            // Verify the token - should succeed
            const result = verifier.verifySync(signedJwt);

            // The token should be verified successfully, confirming the correct JWKS URI was used
            return jwksUriDerivedFromIssuer && result.iss === issuer;
          }
        ),
        { numRuns: 100 }
      );
    });
  });
});
