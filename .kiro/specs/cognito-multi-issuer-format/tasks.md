# Implementation Plan: Cognito Multi-Issuer Format Support

## Overview

This implementation plan covers the minimal changes needed to support both standard and multi-region Cognito issuer formats. The approach registers both issuer formats as separate entries in the existing configuration map, leveraging the existing infrastructure.

## Tasks

- [x] 1. Modify `parseUserPoolId()` to return both issuer formats

  - Update return type to include `multiRegionIssuer` and `multiRegionJwksUri`
  - Keep existing `issuer` and `jwksUri` fields for backward compatibility
  - _Requirements: 2.1, 2.2_

- [x] 2. Add `parseIssuer()` static method

  - Add new static method to parse and validate Cognito issuer URLs
  - Support both standard and multi-region formats
  - Return `null` for invalid formats (or throw for strict validation)
  - _Requirements: 1.3, 4.3_

- [x] 3. Modify constructor to register both issuers

  - [x] 3.1 Update constructor to create two issuer configs per User Pool
    - One for standard issuer format
    - One for multi-region issuer format
    - Both share the same verification properties (clientId, tokenUse, etc.)
    - _Requirements: 1.1, 1.2_

- [x] 4. Update `cacheJwks()` method

  - Modify to cache JWKS for both issuer formats when a User Pool ID is provided
  - Ensure backward compatibility for single User Pool case
  - _Requirements: 2.1.1, 2.1.2_

- [x] 5. Checkpoint - Verify core functionality

  - Ensure all existing tests pass
  - Ensure the library compiles without errors

- [x] 6. Add unit tests for new functionality

  - [x] 6.1 Test `parseUserPoolId()` returns both formats

    - Test with various valid User Pool IDs
    - Test with GovCloud regions
    - _Requirements: 2.1, 2.2_

  - [x] 6.2 Test `parseIssuer()` method

    - Test with valid standard issuer format
    - Test with valid multi-region issuer format
    - Test with invalid issuer formats
    - Test with GovCloud regions
    - _Requirements: 1.3, 4.3_

  - [x] 6.3 Test constructor registers both issuers
    - Verify both issuers are in the config map
    - Verify single User Pool creates two entries
    - Verify multiple User Pools create correct number of entries
    - _Requirements: 1.1, 1.2_

- [x] 7. Add integration tests for verification flows

  - [x] 7.1 Test verify with standard issuer format

    - Create JWT with standard issuer
    - Verify it is accepted
    - Verify correct JWKS endpoint is called
    - _Requirements: 1.1, 2.1_

  - [x] 7.2 Test verify with multi-region issuer format

    - Create JWT with multi-region issuer
    - Verify it is accepted
    - Verify correct JWKS endpoint is called
    - _Requirements: 1.2, 2.2_

  - [x] 7.3 Test rejection of invalid issuer formats

    - Create JWT with invalid issuer
    - Verify it is rejected with appropriate error
    - _Requirements: 1.3, 4.1, 4.2, 4.3_

  - [x] 7.4 Test multi-pool configuration
    - Configure verifier with multiple User Pools
    - Verify tokens from each pool with both formats
    - _Requirements: 5.1, 5.2_

- [x] 8. Test hydrate() and caching behavior

  - [x] 8.1 Test hydrate() fetches from both endpoints

    - Call hydrate() and verify both JWKS URIs are fetched
    - _Requirements: 2.1.3_

  - [x] 8.2 Test cacheJwks() caches for both issuers

    - Call cacheJwks() with a User Pool ID
    - Verify JWKS is cached for both issuer formats
    - _Requirements: 2.1.1, 2.1.2_

  - [x] 8.3 Test cache isolation
    - Verify cache miss on one endpoint doesn't affect the other
    - _Requirements: 2.1.4_

- [x] 9. Add property-based tests

  - [x] 9.1 Property test for issuer format acceptance

    - **Property 1: Both issuer formats are accepted for valid tokens**
    - **Validates: Requirements 1.1, 1.2**

  - [x] 9.2 Property test for invalid issuer rejection

    - **Property 2: Invalid issuer formats are rejected**
    - **Validates: Requirements 1.3, 4.3**

  - [x] 9.3 Property test for JWKS URI derivation
    - **Property 3: JWKS URI is derived from token's issuer**
    - **Validates: Requirements 2.1, 2.2**

- [x] 10. Final checkpoint
  - Ensure all tests pass
  - Ensure no regressions in existing functionality
  - Verify backward compatibility

## Notes

- All tests are required for comprehensive coverage
- The implementation leverages existing infrastructure to minimize changes
- Estimated total code changes: ~55 lines in `src/cognito-verifier.ts`
- All existing tests should continue to pass without modification
