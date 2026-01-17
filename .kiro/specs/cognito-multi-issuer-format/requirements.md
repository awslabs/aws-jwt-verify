# Requirements Document

## Introduction

This document specifies the requirements for enhancing the `aws-jwt-verify` library to support an additional Cognito issuer format. Amazon Cognito User Pools with multi-region replication enabled use a different issuer URL format (`https://issuer.cognito-idp.{region}.amazonaws.com/{userPoolId}`) compared to standard User Pools (`https://cognito-idp.{region}.amazonaws.com/{userPoolId}`). The library must be updated to accept JWTs with either issuer format.

## Glossary

- **CognitoJwtVerifier**: The class in the library responsible for verifying JWTs signed by Amazon Cognito User Pools.
- **Issuer**: The `iss` claim in a JWT that identifies the principal that issued the token.
- **User_Pool_ID**: A unique identifier for an Amazon Cognito User Pool in the format `{region}_{alphanumeric}`.
- **JWKS_URI**: The URL endpoint where the JSON Web Key Set can be fetched for signature verification.
- **Standard_Issuer_Format**: The issuer format for standard User Pools: `https://cognito-idp.{region}.amazonaws.com/{userPoolId}`.
- **MultiRegion_Issuer_Format**: The issuer format for multi-region replication enabled User Pools: `https://issuer.cognito-idp.{region}.amazonaws.com/{userPoolId}`.

## Requirements

### Requirement 1: Support Both Issuer Formats

**User Story:** As a developer using aws-jwt-verify, I want the library to accept JWTs with either the standard or multi-region Cognito issuer format, so that my application works with both standard and multi-region User Pools.

#### Acceptance Criteria

1. WHEN a JWT with the Standard_Issuer_Format is verified, THE CognitoJwtVerifier SHALL accept the token if all other validation checks pass.
2. WHEN a JWT with the MultiRegion_Issuer_Format is verified, THE CognitoJwtVerifier SHALL accept the token if all other validation checks pass.
3. WHEN a JWT with an issuer format that does not match either the Standard_Issuer_Format or MultiRegion_Issuer_Format for the configured User_Pool_ID, THE CognitoJwtVerifier SHALL reject the token with an appropriate error.

### Requirement 2: Derive JWKS URI from Token Issuer

**User Story:** As a developer, I want the library to fetch the JWKS from the correct endpoint based on the token's issuer, so that signature verification works correctly regardless of which issuer format was used.

#### Acceptance Criteria

1. WHEN a JWT with the Standard_Issuer_Format is verified, THE CognitoJwtVerifier SHALL fetch the JWKS from `https://cognito-idp.{region}.amazonaws.com/{userPoolId}/.well-known/jwks.json`.
2. WHEN a JWT with the MultiRegion_Issuer_Format is verified, THE CognitoJwtVerifier SHALL fetch the JWKS from `https://issuer.cognito-idp.{region}.amazonaws.com/{userPoolId}/.well-known/jwks.json`.

### Requirement 2.1: JWKS Caching for Both Endpoints

**User Story:** As a developer, I want the library to cache JWKS from both issuer endpoints independently, so that performance is optimized when my application receives tokens with different issuer formats.

#### Acceptance Criteria

1. WHEN a JWT with the Standard_Issuer_Format is verified, THE CognitoJwtVerifier SHALL cache the JWKS using the standard JWKS URI as the cache key.
2. WHEN a JWT with the MultiRegion_Issuer_Format is verified, THE CognitoJwtVerifier SHALL cache the JWKS using the multi-region JWKS URI as the cache key.
3. WHEN the JWKS cache is hydrated via the `hydrate()` method, THE CognitoJwtVerifier SHALL fetch and cache JWKS from both the standard and multi-region endpoints for each configured User Pool.
4. WHEN a JWK is not found in the cached JWKS for one endpoint, THE CognitoJwtVerifier SHALL fetch fresh JWKS from that specific endpoint without affecting the cache for the other endpoint.

### Requirement 3: Backward Compatibility

**User Story:** As a developer with an existing integration, I want the library update to be backward compatible, so that my existing code continues to work without modifications.

#### Acceptance Criteria

1. THE CognitoJwtVerifier SHALL maintain the existing API signature for the `create()` method.
2. THE CognitoJwtVerifier SHALL maintain the existing API signature for the `verify()` and `verifySync()` methods.
3. WHEN a developer upgrades to the new version, THE CognitoJwtVerifier SHALL work with existing code without requiring changes.

### Requirement 4: Issuer Validation

**User Story:** As a security-conscious developer, I want the library to validate that the token's issuer corresponds to the configured User Pool, so that tokens from other User Pools are rejected.

#### Acceptance Criteria

1. WHEN a JWT's issuer contains a User_Pool_ID that does not match the configured User_Pool_ID, THE CognitoJwtVerifier SHALL reject the token.
2. WHEN a JWT's issuer contains a region that does not match the region in the configured User_Pool_ID, THE CognitoJwtVerifier SHALL reject the token.
3. WHEN a JWT's issuer uses an unrecognized domain pattern (not cognito-idp or issuer.cognito-idp), THE CognitoJwtVerifier SHALL reject the token.

### Requirement 5: Multiple User Pools with Mixed Issuer Formats

**User Story:** As a developer supporting multiple User Pools, I want the library to handle tokens from different User Pools that may use different issuer formats, so that my multi-tenant application works correctly.

#### Acceptance Criteria

1. WHEN the CognitoJwtVerifier is configured with multiple User Pools, THE CognitoJwtVerifier SHALL accept tokens with either issuer format from any of the configured User Pools.
2. WHEN verifying a token, THE CognitoJwtVerifier SHALL match the token's issuer to the correct User Pool configuration based on the User_Pool_ID extracted from the issuer.
