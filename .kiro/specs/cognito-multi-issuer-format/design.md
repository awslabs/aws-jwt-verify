# Design Document: Cognito Multi-Issuer Format Support

## Overview

This design document describes the minimal changes required to support the multi-region Cognito issuer format (`https://issuer.cognito-idp.{region}.amazonaws.com/{userPoolId}`) alongside the standard format (`https://cognito-idp.{region}.amazonaws.com/{userPoolId}`).

### Design Principle: Minimal Changes

The goal is to make the smallest possible changes to the existing codebase while achieving full functionality. We will:

- Reuse existing infrastructure (JWKS cache, base verifier class) as-is
- Add new methods only where necessary
- Modify existing methods minimally
- Avoid restructuring the configuration storage

## Architecture

### Key Insight

The existing `JwtVerifierBase` already supports multiple issuers via its `issuersConfig` map. Instead of changing the storage structure, we can:

1. Register **both** issuer formats as separate entries in the map during `create()`
2. The existing lookup by `iss` claim will then work naturally for either format

This approach requires minimal changes:

- Modify `parseUserPoolId()` to return both issuers
- Modify the constructor to register both issuers pointing to the same config
- Add a helper to parse/validate incoming issuers

### Current vs Proposed Flow

**Current**: One issuer registered per User Pool
**Proposed**: Two issuers registered per User Pool (standard + multi-region), both pointing to the same verification config but with their respective JWKS URIs

## Components and Interfaces

### Modified: `CognitoJwtVerifier.parseUserPoolId()`

Minimal change: Return both issuer formats instead of just one.

```typescript
// BEFORE
public static parseUserPoolId(userPoolId: string): {
  issuer: string;
  jwksUri: string;
} {
  // ... validation ...
  const issuer = `https://cognito-idp.${region}.amazonaws.com/${userPoolId}`;
  return {
    issuer,
    jwksUri: `${issuer}/.well-known/jwks.json`,
  };
}

// AFTER
public static parseUserPoolId(userPoolId: string): {
  issuer: string;           // standard issuer (for backward compat)
  jwksUri: string;          // standard JWKS URI (for backward compat)
  multiRegionIssuer: string;
  multiRegionJwksUri: string;
} {
  // ... validation (unchanged) ...
  const standardIssuer = `https://cognito-idp.${region}.amazonaws.com/${userPoolId}`;
  const multiRegionIssuer = `https://issuer.cognito-idp.${region}.amazonaws.com/${userPoolId}`;
  return {
    issuer: standardIssuer,
    jwksUri: `${standardIssuer}/.well-known/jwks.json`,
    multiRegionIssuer,
    multiRegionJwksUri: `${multiRegionIssuer}/.well-known/jwks.json`,
  };
}
```

### Modified: `CognitoJwtVerifier` Constructor

Minimal change: Register both issuers in the config map.

```typescript
// BEFORE
private constructor(
  props: CognitoJwtVerifierProperties | CognitoJwtVerifierMultiProperties[],
  jwksCache?: JwksCache
) {
  const issuerConfig = Array.isArray(props)
    ? (props.map((p) => ({
        ...p,
        ...CognitoJwtVerifier.parseUserPoolId(p.userPoolId),
        audience: null,
      })) as IssuerConfig[])
    : ({
        ...props,
        ...CognitoJwtVerifier.parseUserPoolId(props.userPoolId),
        audience: null,
      } as IssuerConfig);
  super(issuerConfig, jwksCache);
}

// AFTER
private constructor(
  props: CognitoJwtVerifierProperties | CognitoJwtVerifierMultiProperties[],
  jwksCache?: JwksCache
) {
  const propsArray = Array.isArray(props) ? props : [props];
  const issuerConfigs: IssuerConfig[] = [];

  for (const p of propsArray) {
    const parsed = CognitoJwtVerifier.parseUserPoolId(p.userPoolId);
    const baseConfig = {
      ...p,
      userPoolId: p.userPoolId,
      audience: null,
    };

    // Register standard issuer config
    issuerConfigs.push({
      ...baseConfig,
      issuer: parsed.issuer,
      jwksUri: parsed.jwksUri,
    } as IssuerConfig);

    // Register multi-region issuer config
    issuerConfigs.push({
      ...baseConfig,
      issuer: parsed.multiRegionIssuer,
      jwksUri: parsed.multiRegionJwksUri,
    } as IssuerConfig);
  }

  super(issuerConfigs, jwksCache);
}
```

### New: `CognitoJwtVerifier.parseIssuer()` (Optional Helper)

Add a static method to validate and parse Cognito issuers. This is useful for users who want to validate issuers manually.

```typescript
/**
 * Parse a Cognito issuer URL to extract the User Pool ID and determine the format.
 * Supports both standard and multi-region issuer formats.
 */
public static parseIssuer(issuer: string): {
  userPoolId: string;
  region: string;
  format: "standard" | "multiRegion";
} | null {
  // Standard format: https://cognito-idp.{region}.amazonaws.com/{userPoolId}
  const standardMatch = issuer.match(
    /^https:\/\/cognito-idp\.([a-z]{2}-(gov-)?[a-z]+-\d)\.amazonaws\.com\/([a-z]{2}-(gov-)?[a-z]+-\d_[a-zA-Z0-9]+)$/
  );
  if (standardMatch) {
    return {
      region: standardMatch[1],
      userPoolId: standardMatch[3],
      format: "standard",
    };
  }

  // Multi-region format: https://issuer.cognito-idp.{region}.amazonaws.com/{userPoolId}
  const multiRegionMatch = issuer.match(
    /^https:\/\/issuer\.cognito-idp\.([a-z]{2}-(gov-)?[a-z]+-\d)\.amazonaws\.com\/([a-z]{2}-(gov-)?[a-z]+-\d_[a-zA-Z0-9]+)$/
  );
  if (multiRegionMatch) {
    return {
      region: multiRegionMatch[1],
      userPoolId: multiRegionMatch[3],
      format: "multiRegion",
    };
  }

  return null;
}
```

### Modified: `hydrate()` Method

The base class `hydrate()` already iterates over all issuer configs. Since we now register two configs per User Pool, it will automatically fetch JWKS from both endpoints. **No change needed.**

### Modified: `cacheJwks()` Method

Minor change: When caching JWKS for a User Pool, cache for both issuers.

```typescript
public cacheJwks(
  ...[jwks, userPoolId]: MultiIssuer extends false
    ? [jwks: Jwks, userPoolId?: string]
    : [jwks: Jwks, userPoolId: string]
): void {
  // Find both issuer configs for this User Pool
  const parsed = userPoolId
    ? CognitoJwtVerifier.parseUserPoolId(userPoolId)
    : null;

  if (parsed) {
    // Cache for both issuers
    const standardConfig = this.getIssuerConfig(parsed.issuer);
    const multiRegionConfig = this.getIssuerConfig(parsed.multiRegionIssuer);
    super.cacheJwks(jwks, standardConfig.issuer);
    super.cacheJwks(jwks, multiRegionConfig.issuer);
  } else {
    // Single User Pool case - cache for both issuers
    for (const config of this.issuersConfig.values()) {
      this.jwksCache.addJwks(config.jwksUri, jwks);
    }
    // Clear public key cache for all issuers
    for (const config of this.issuersConfig.values()) {
      this.publicKeyCache.clearCache(config.issuer);
    }
  }
}
```

## Data Models

No new data models required. The existing `IssuerConfig` type is sufficient.

## Summary of Changes

| File                      | Change                                      | Lines Changed (Est.) |
| ------------------------- | ------------------------------------------- | -------------------- |
| `src/cognito-verifier.ts` | Modify `parseUserPoolId()` return type      | ~5                   |
| `src/cognito-verifier.ts` | Modify constructor to register both issuers | ~15                  |
| `src/cognito-verifier.ts` | Add `parseIssuer()` static method           | ~25                  |
| `src/cognito-verifier.ts` | Modify `cacheJwks()` to handle both issuers | ~10                  |

**Total estimated changes: ~55 lines**

## What Stays the Same

- `JwtVerifierBase` class - no changes
- `SimpleJwksCache` - no changes
- `verify()` and `verifySync()` methods - no changes (they use base class implementation)
- `validateCognitoJwtFields()` - no changes
- Error types - no changes
- All other verifiers (`JwtVerifier`, `AlbJwtVerifier`) - no changes

## Correctness Properties

_A property is a characteristic or behavior that should hold true across all valid executions of a system—essentially, a formal statement about what the system should do._

**Property 1: Both issuer formats are accepted for valid tokens**

_For any_ valid JWT signed by a configured User Pool, if the issuer matches either the standard format (`https://cognito-idp.{region}.amazonaws.com/{userPoolId}`) or the multi-region format (`https://issuer.cognito-idp.{region}.amazonaws.com/{userPoolId}`), the CognitoJwtVerifier should accept the token.

**Validates: Requirements 1.1, 1.2**

---

**Property 2: Invalid issuer formats are rejected**

_For any_ JWT with an issuer that does not match either the standard or multi-region Cognito issuer format for the configured User Pool ID, the CognitoJwtVerifier should reject the token with a ParameterValidationError.

**Validates: Requirements 1.3, 4.3**

---

**Property 3: JWKS URI is derived from token's issuer**

_For any_ JWT being verified, the JWKS URI used for fetching keys should match the issuer's domain (standard or multi-region), ensuring the correct endpoint is used.

**Validates: Requirements 2.1, 2.2**

---

**Property 4: Issuer must match configured User Pool**

_For any_ JWT with an issuer containing a User Pool ID that does not match the configured User Pool, the CognitoJwtVerifier should reject the token.

**Validates: Requirements 4.1, 4.2**

---

**Property 5: Multi-pool configuration accepts tokens from any configured pool**

_For any_ CognitoJwtVerifier configured with multiple User Pools, and _for any_ valid JWT from any of those pools using either issuer format, the verifier should accept the token.

**Validates: Requirements 5.1, 5.2**

---

**Property 6: Hydrate fetches JWKS from both endpoints**

_For any_ CognitoJwtVerifier with configured User Pools, calling `hydrate()` should result in JWKS being fetched from both the standard and multi-region endpoints for each configured pool.

**Validates: Requirements 2.1.3**

---

**Property 7: Cache isolation between endpoints**

_For any_ cache miss on one JWKS endpoint (standard or multi-region), fetching fresh JWKS from that endpoint should not invalidate or affect the cached JWKS from the other endpoint.

**Validates: Requirements 2.1.4**

## Error Handling

### Existing Error Handling (Unchanged)

The existing error handling remains the same:

- `ParameterValidationError`: Invalid User Pool ID or issuer not configured
- `JwtExpiredError`: Token has expired
- `JwtInvalidSignatureError`: Signature verification failed
- `CognitoJwtInvalidClientIdError`: Client ID doesn't match
- `CognitoJwtInvalidTokenUseError`: Token use doesn't match
- `KidNotFoundInJwksError`: Key ID not found in JWKS

When a token has an issuer that doesn't match any configured issuer (neither standard nor multi-region for any configured User Pool), the existing `getIssuerConfig()` will throw `ParameterValidationError` with message `"issuer not configured: {issuer}"`.

## Testing Strategy

### Unit Tests

- `parseUserPoolId()` returns both issuer formats
- `parseIssuer()` correctly identifies standard vs multi-region format
- `parseIssuer()` returns null for invalid formats
- Constructor registers both issuers for each User Pool
- `cacheJwks()` caches for both issuers

### Property-Based Tests

- **Property 1**: Generate valid tokens with both issuer formats, verify acceptance
- **Property 2**: Generate tokens with invalid issuers, verify rejection
- **Property 3**: Verify correct JWKS URI is used based on issuer format

### Integration Tests

- Verify token with standard issuer format
- Verify token with multi-region issuer format
- Verify `hydrate()` fetches from both endpoints
- Verify multi-pool configuration works with mixed formats

### Test Configuration

- Property-based tests: minimum 100 iterations
- Use `nock` for mocking JWKS endpoints
- Use existing test utilities for JWT generation
