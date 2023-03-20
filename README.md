# AWS JWT Verify

**JavaScript** library for **verifying** JWTs signed by **Amazon Cognito**, and any **OIDC-compatible IDP** that signs JWTs with **RS256** / **RS384** / **RS512**.

## Installation

`npm install aws-jwt-verify`

This library can be used with Node.js 14 or higher. If used with TypeScript, TypeScript 4 or higher is required.

This library can also be used in Web browsers.

## Basic usage

### Amazon Cognito

```typescript
import { CognitoJwtVerifier } from "aws-jwt-verify";

// Verifier that expects valid access tokens:
const verifier = CognitoJwtVerifier.create({
  userPoolId: "<user_pool_id>",
  tokenUse: "access",
  clientId: "<client_id>",
});

try {
  const payload = await verifier.verify(
    "eyJraWQeyJhdF9oYXNoIjoidk..." // the JWT as string
  );
  console.log("Token is valid. Payload:", payload);
} catch {
  console.log("Token not valid!");
}
```

See all verify parameters for Amazon Cognito JWTs [here](#cognitojwtverifier-verify-parameters).

### Other IDPs

```typescript
import { JwtRsaVerifier } from "aws-jwt-verify";

const verifier = JwtRsaVerifier.create({
  issuer: "https://example.com/", // set this to the expected "iss" claim on your JWTs
  audience: "<audience>", // set this to the expected "aud" claim on your JWTs
  jwksUri: "https://example.com/.well-known/jwks.json", // set this to the JWKS uri from your OpenID configuration
});

try {
  const payload = await verifier.verify("eyJraWQeyJhdF9oYXNoIjoidk...");
  console.log("Token is valid. Payload:", payload);
} catch {
  console.log("Token not valid!");
}
```

See all verify parameters for JWTs from any IDP [here](#jwtrsaverifier-verify-parameters).

## Philosophy of this library

- Do one thing and do it well. Focus solely on **verifying** JWTs.
- Pure **TypeScript** library that can be used in **Node.js** v14 and above (both CommonJS and ESM supported), as well in the modern evergreen Web browser.
- Support both **Amazon Cognito** as well as any other **OIDC-compatible IDP** as first class citizen.
- **0** runtime dependencies, batteries included. This library includes all necessary code to validate RS256/RS384/RS512-signed JWTs. E.g. it contains a simple (and pluggable) **HTTP** helper to fetch the **JWKS** from the JWKS URI, and it includes a simple **ASN.1** encoder to transform JWKs into **DER-encoded RSA public keys** (in order to verify JWTs with Node.js native crypto calls).
- Opinionated towards the **best practices** as described by the IETF in [JSON Web Token Best Current Practices](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-jwt-bcp-02#section-3).
- Make it **easy** for users to use this library in a **secure** way. For example, this library requires users to specify `issuer` and `audience`, as these should be checked for (see best practices linked to above).

Currently, only signature algorithms **RS256** , **RS384** and **RS512** are supported.

## Intended Usage

This library was specifically designed to be easy to use in:

- [API Gateway Lambda authorizers](https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-use-lambda-authorizer.html)
- [AppSync Lambda authorizers](https://docs.aws.amazon.com/appsync/latest/devguide/security-authz.html#aws-lambda-authorization)
- [CloudFront Lambda@Edge](https://docs.aws.amazon.com/lambda/latest/dg/lambda-edge.html)
- Node.js APIs, e.g. running in AWS Fargate, that need to verify incoming JWTs

## Usage in the Web browser

Many webdev toolchains (e.g. [CreateReactApp](https://github.com/facebook/create-react-app)) make including `npm` libraries in your web app easy, in which case using this library in your web app should just work.

If you need to bundle this library manually yourself, be aware that this library uses [subpath imports](https://nodejs.org/api/packages.html#subpath-imports), to automatically select the Web crypto implementation when bundling for the browser. This is supported out-of-the-box by [webpack](https://webpack.js.org/) and [esbuild](https://esbuild.github.io/). An example of using this library in a Vite web app, with Cypress tests, is included in this repository [here](tests/vite-app/).

## Table of Contents

- [Verifying JWTs from Amazon Cognito](#Verifying-JWTs-from-Amazon-Cognito)
  - [Verify parameters](#cognitojwtverifier-verify-parameters)
  - [Checking scope](#checking-scope)
  - [Custom JWT and JWK checks](#custom-jwt-and-jwk-checks)
  - [Trusting multiple User Pools](#trusting-multiple-user-pools)
  - [Using the generic JWT RSA verifier for Cognito JWTs](#using-the-generic-jwt-rsa-verifier-for-cognito-jwts)
- [Verifying JWTs from any OIDC-compatible IDP](#verifying-jwts-from-any-oidc-compatible-idp)
  - [Verify parameters](#jwtrsaverifier-verify-parameters)
- [Peeking inside unverified JWTs](#peeking-inside-unverified-jwts)
- [Verification errors](#verification-errors)
  - [Peek inside invalid JWTs](#peek-inside-invalid-jwts)
- [The JWKS cache](#the-jwks-cache)
  - [Loading the JWKS from file](#loading-the-jwks-from-file)
  - [Rate limiting](#rate-limiting)
  - [Explicitly hydrating the JWKS cache](#explicitly-hydrating-the-jwks-cache)
  - [Clearing the JWKS cache](#clearing-the-jwks-cache)
  - [Customizing the JWKS cache](#customizing-the-jwks-cache)
  - [Sharing the JWKS cache amongst different verifiers](#sharing-the-jwks-cache-amongst-different-verifiers)
  - [Using a different `JsonFetcher` with `SimpleJwksCache`](#using-a-different-jsonfetcher-with-simplejwkscache)
  - [Configuring the JWKS response timeout and other HTTP options with `JsonFetcher`](#configuring-the-jwks-response-timeout-and-other-http-options-with-jsonfetcher)
  - [Using a different `penaltyBox` with `SimpleJwksCache`](#using-a-different-penaltybox-with-simplejwkscache)
- [Usage examples](#Usage-examples)
  - [CloudFront Lambda@Edge](#cloudfront-lambdaedge)
  - [API Gateway Lambda Authorizer - REST](#api-gateway-lambda-authorizer---rest)
  - [HTTP API Authorizer](#http-api-lambda-authorizer)
  - [AppSync Lambda Authorizer](#appsync-lambda-authorizer)
  - [Fastify](#fastify)
  - [Express](#express)
- [Security](#security)
- [License](#license)

## Verifying JWTs from Amazon Cognito

Create a `CognitoJwtVerifier` instance and use it to verify JWTs:

```typescript
import { CognitoJwtVerifier } from "aws-jwt-verify";

// Verifier that expects valid access tokens:
const verifier = CognitoJwtVerifier.create({
  userPoolId: "<user_pool_id>",
  tokenUse: "access",
  clientId: "<client_id>",
});

try {
  const payload = await verifier.verify(
    "eyJraWQeyJhdF9oYXNoIjoidk..." // the JWT as string
  );
  console.log("Token is valid. Payload:", payload);
} catch {
  console.log("Token not valid!");
}
```

You can also use `verifySync`, if you've made sure the JWK has already been cached, see further below.

### `CognitoJwtVerifier` `verify` parameters

Except the User Pool ID, parameters provided when creating the `CognitoJwtVerifier` act as defaults, that can be overridden upon calling `verify` or `verifySync`.

Supported parameters are:

- `tokenUse` (mandatory): verify that the JWT's `token_use` claim matches your expectation. Set to either `id` or `access`. Set to `null` to skip checking `token_use`.
- `clientId` (mandatory): verify that the JWT's `aud` (id token) or `client_id` (access token) claim matches your expectation. Provide a string, or an array of strings to allow multiple client ids (i.e. one of these client ids must match the JWT). Set to `null` to skip checking client id (not recommended unless you know what you are doing).
- `groups` (optional): verify that the JWT's `cognito:groups` claim matches your expectation. Provide a string, or an array of strings to allow multiple groups (i.e. one of these groups must match the JWT).
- `scope` (optional): verify that the JWT's `scope` claim matches your expectation (only of use for access tokens). Provide a string, or an array of strings to allow multiple scopes (i.e. one of these scopes must match the JWT). See also [Checking scope](#Checking-scope).
- `graceSeconds` (optional, default `0`): to account for clock differences between systems, provide the number of seconds beyond JWT expiry (`exp` claim) or before "not before" (`nbf` claim) you will allow.
- `customJwtCheck` (optional): your custom function with additional JWT (and JWK) checks to execute (see also below).
- `includeRawJwtInErrors` (optional, default `false`): set to `true` if you want to peek inside the invalid JWT when verification fails. Refer to: [Peek inside invalid JWTs](#peek-inside-invalid-jwts).

```typescript
import { CognitoJwtVerifier } from "aws-jwt-verify";

const verifier = CognitoJwtVerifier.create({
  userPoolId: "<user_pool_id>", // mandatory, can't be overridden upon calling verify
  tokenUse: "id", // needs to be specified here or upon calling verify
  clientId: "<client_id>", // needs to be specified here or upon calling verify
  groups: "admins", // optional
  graceSeconds: 0, // optional
  scope: "my-api/read", // optional
  customJwtCheck: (payload, header, jwk) => {}, // optional
});

try {
  const payload = await verifier.verify("eyJraWQeyJhdF9oYXNoIjoidk...", {
    groups: "users", // Cognito groups overridden: should be users (not admins)
  });
  console.log("Token is valid. Payload:", payload);
} catch {
  console.log("Token not valid!");
}
```

### Checking scope

If you provide scopes to the `CognitoJwtVerifier`, the verifier will make sure the `scope` claim in the JWT includes at least one of those scopes:

```typescript
import { CognitoJwtVerifier } from "aws-jwt-verify";

const verifier = CognitoJwtVerifier.create({
  userPoolId: "<user_pool_id>",
  tokenUse: "access", // scopes are only present on Cognito access tokens
  clientId: "<client_id>",
  scope: ["my-api:write", "my-api:admin"],
});

try {
  const payload = await verifier.verify("eyJraWQeyJhdF9oYXNoIjoidk...");
  console.log("Token is valid. Payload:", payload);
} catch {
  console.log("Token not valid!");
}
```

So a JWT payload like the following would have a valid scope:

```javascript
{
  "client_id": "<client_id>",
  "scope": "my-api:write someotherscope yetanotherscope", // scope string is split on spaces to gather the array of scopes to compare with
  "iat": 1234567890,
  "...": "..."
}
```

This scope would not be valid:

```javascript
{
  "client_id": "<client_id>",
  "scope": "my-api:read someotherscope yetanotherscope", // Neither "my-api:write" nor "my-api:admin" present
  "iat": 1234567890,
  "...": "..."
}
```

### Custom JWT and JWK checks

It's possible to provide a function with your own custom JWT checks. This function will be called if the JWT is valid, at the end of the JWT verification.

The function will be called with:

- the decoded JWT header
- the decoded JWT payload
- the JWK that was used to verify the JWT

Throw an error in this function if you want to reject the JWT.

```typescript
import { CognitoJwtVerifier } from "aws-jwt-verify";

const idTokenVerifier = CognitoJwtVerifier.create({
  userPoolId: "<user_pool_id>",
  tokenUse: "id",
  clientId: "<client_id>",
  customJwtCheck: async ({ header, payload, jwk }) => {
    if (header.someHeaderField !== "expected") {
      throw new Error("something wrong with the header");
    }
    if (payload.somePayloadField !== "expected") {
      throw new Error("something wrong with the payload");
    }
    if (jwk.someJwkfField !== "expected") {
      throw new Error("something wrong with the jwk");
    }
    await someAsyncCheck(...); // can call out to a DB or do whatever
  },
});

// This will now throw, even if the JWT is otherwise valid, if your custom function throws:
await idTokenVerifier.verify("eyJraWQeyJhdF9oYXNoIjoidk...");
```

Note that `customJwtCheck` may be an async function, but only if you use `verify` (not supported for `verifySync`).

### Trusting multiple User Pools

If you want to allow JWTs from multiple User Pools, provide an array with these User Pools upon creating the verifier:

```typescript
import { CognitoJwtVerifier } from "aws-jwt-verify";

// This verifier will trust both User Pools
const idTokenVerifier = CognitoJwtVerifier.create([
  {
    userPoolId: "<user_pool_id>",
    tokenUse: "id",
    clientId: "<client_id>", // clientId is mandatory at verifier level now, to disambiguate between User Pools
  },
  {
    userPoolId: "<user_pool_id_2>",
    tokenUse: "id",
    clientId: "<client_id_2>",
  },
]);

try {
  const idTokenPayload = await idTokenVerifier.verify(
    "eyJraWQeyJhdF9oYXNoIjoidk..." // token must be signed by either of the User Pools
  );
  console.log("Token is valid. Payload:", idTokenPayload);
} catch {
  console.log("Token not valid!");
}
```

### Using the generic JWT RSA verifier for Cognito JWTs

The generic `JwtRsaVerifier` (see [below](#verifying-jwts-from-any-oidc-compatible-idp)) can also be used for Cognito, which is useful if you want to define a verifier that trusts multiple IDPs, i.e. Cognito and another IDP.

In this case, leave `audience` to `null`, but rather manually add `validateCognitoJwtFields` in the `customJwtCheck`.
(Only Cognito ID tokens have an `audience` claim, Cognito Access token have a `client_id` claim instead. The `validateCognitoJwtFields` function handles this difference automatically for you)

```typescript
import { JwtRsaVerifier } from "aws-jwt-verify";
import { validateCognitoJwtFields } from "aws-jwt-verify/cognito-verifier";

const verifier = JwtRsaVerifier.create([
  {
    issuer: "https://cognito-idp.eu-west-1.amazonaws.com/<user_pool_id>",
    audience: null, // audience (~clientId) is checked instead, by the Cognito specific checks below
    customJwtCheck: ({ payload }) =>
      validateCognitoJwtFields(payload, {
        tokenUse: "access", // set to "id" or "access" (or null if both are fine)
        clientId: "<client_id>", // provide the client id, or an array of client ids (or null if you do not want to check client id)
        groups: ["admin", "others"], // optional, provide a group name, or array of group names
      }),
  },
  {
    issuer: "https://example.com/my/other/idp",
    audience: "myaudience", // do specify audience for other IDPs
  },
]);
```

## Verifying JWTs from any OIDC-compatible IDP

The generic `JwtRsaVerifier` works for any OIDC-compatible IDP that signs JWTs with RS256/RS384/RS512:

```typescript
import { JwtRsaVerifier } from "aws-jwt-verify";

const verifier = JwtRsaVerifier.create({
  issuer: "https://example.com/", // set this to the expected "iss" claim on your JWTs
  audience: "<audience>", // set this to the expected "aud" claim on your JWTs
  jwksUri: "https://example.com/.well-known/jwks.json", // set this to the JWKS uri from your OpenID configuration
});

try {
  const payload = await verifier.verify("eyJraWQeyJhdF9oYXNoIjoidk...");
  console.log("Token is valid. Payload:", payload);
} catch {
  console.log("Token not valid!");
}
```

Support Multiple IDP's:

```typescript
const verifier = JwtRsaVerifier.create([
  {
    issuer: "https://example.com/idp1",
    audience: "expectedAudienceIdp1",
  },
  {
    issuer: "https://example.com/idp2",
    audience: "expectedAudienceIdp2",
  },
]);

try {
  const otherPayload = await verifier.verify("eyJraWQeyJhdF9oYXNoIjoidk..."); // Token must be from either idp1 or idp2
  console.log("Token is valid. Payload:", otherPayload);
} catch {
  console.log("Token not valid!");
}
```

### `JwtRsaVerifier` `verify` parameters

Except `issuer`, parameters provided when creating the `JwtRsaVerifier` act as defaults, that can be overridden upon calling `verify` or `verifySync`.

Supported parameters are:

- `jwksUri` (optional, can only be provided at verifier level): the URI where the JWKS can be downloaded from. To find this URI for your IDP, consult your IDP's OpenId configuration (e.g. by opening the OpenId configuration in your browser). Usually, it is `${issuer}/.well-known/jwks.json`, which is the default value that will be used if you don't explicitly provide `jwksUri`.
- `audience` (mandatory): verify that the JWT's `aud` claim matches your expectation. Provide a string, or an array of strings to allow multiple client ids (i.e. one of these audiences must match the JWT). Set to `null` to skip checking audience (not recommended unless you know what you are doing). Note that a JWT's `aud` claim might be an array of audiences. The `JwtRsaVerifier` will in that case make sure that at least one of these audiences matches with at least one of the audiences that were provided to the verifier.
- `scope` (optional): verify that the JWT's `scope` claim matches your expectation (only of use for access tokens). Provide a string, or an array of strings to allow multiple scopes (i.e. one of these scopes must match the JWT). See also [Checking scope](#checking-scope).
- `graceSeconds` (optional, default `0`): to account for clock differences between systems, provide the number of seconds beyond JWT expiry (`exp` claim) or before "not before" (`nbf` claim) you will allow.
- `customJwtCheck` (optional): your custom function with additional JWT checks to execute (see [Custom JWT and JWK checks](#custom-jwt-and-jwk-checks)).
- `includeRawJwtInErrors` (optional, default `false`): set to `true` if you want to peek inside the invalid JWT when verification fails. Refer to: [Peek inside invalid JWTs](#peek-inside-invalid-jwts).

## Peeking inside unverified JWTs

You can peek into the payload of an unverified JWT as follows.

Note: this does NOT verify a JWT, do not trust the returned payload and header! For most use cases, you would not want to call this function directly yourself, rather you would call `verify()` with the JWT, which would call this function (and others) for you.

```typescript
import { decomposeUnverifiedJwt } from "aws-jwt-verify/jwt";

// danger! payload is sanity checked and JSON-parsed, but otherwise unverified, trust nothing in it!
const { payload } = decomposeUnverifiedJwt(
  "eyJraWQeyJhdF9oYXNoIjoidk..." // the JWT as string
);
```

## Verification errors

When verification of a JWT fails, this library will throw an error. All errors are defined in [src/error.ts](./src/error.ts) and can be imported and tested for like so:

```typescript
import { CognitoJwtVerifier } from "aws-jwt-verify";
import { JwtExpiredError } from "aws-jwt-verify/error";

const verifier = CognitoJwtVerifier.create({
  userPoolId: "<user_pool_id>",
  tokenUse: "access",
  clientId: "<client_id>",
});

try {
  const payload = await verifier.verify(
    "eyJraWQeyJhdF9oYXNoIjoidk..." // the JWT as string
  );
} catch (err) {
  // An error is thrown, so the JWT is not valid
  // Use `instanceof` to test for specific error cases:
  if (err instanceof JwtExpiredError) {
    console.error("JWT expired!");
  }
  throw err;
}
```

### Peek inside invalid JWTs

If you want to peek inside invalid JWTs, set `includeRawJwtInErrors` to `true` when creating the verifier. The thrown error will then include the raw JWT:

```typescript
import { CognitoJwtVerifier } from "aws-jwt-verify";
import { JwtInvalidClaimError } from "aws-jwt-verify/error";

const verifier = CognitoJwtVerifier.create({
  userPoolId: "<user_pool_id>",
  tokenUse: "access",
  clientId: "<client_id>",
  includeRawJwtInErrors: true, // can also be specified as parameter to the `verify` call
});

try {
  const payload = await verifier.verify(
    "eyJraWQeyJhdF9oYXNoIjoidk..." // the JWT as string
  );
} catch (err) {
  if (err instanceof JwtInvalidClaimError) {
    // You can log the payload of the raw JWT, e.g. to aid in debugging and alerting on authentication errors
    // Be careful not to disclose information on the error reason to the the client
    console.error("JWT invalid because:", err.message);
    console.error("Raw JWT:", err.rawJwt.payload);
  }
  throw new Error("Unauthorized");
}
```

The `instanceof` check in the `catch` block above is crucial, because not all errors will include the rawJwt, only errors that subclass `JwtInvalidClaimError` will. In order to understand why this makes sense, you should know that this library verifies JWTs in 3 stages, that all must succeed for the JWT to be considered valid:

- Stage 1: Verify JWT structure and JSON parse the JWT
- Stage 2: Verify JWT cryptographic signature (i.e. RS256/RS384/RS512)
- Stage 3: Verify JWT claims (such as e.g. its expiration)

Only in case of stage 3 verification errors, will the raw JWT be included in the error (if you set `includeRawJwtInErrors` to `true`). This way, when you look at the invalid raw JWT in the error, you'll know that its structure and signature are at least valid (stages 1 and 2 succeeded).

Note that if you use [custom JWT checks](#custom-jwt-and-jwk-checks), you are in charge of throwing errors in your custom code. You can (optionally) subclass your errors from `JwtInvalidClaimError`, so that the raw JWT will be included on the errors you throw as well:

```typescript
import { CognitoJwtVerifier } from "aws-jwt-verify";
import { JwtInvalidClaimError } from "aws-jwt-verify/error";

class CustomError extends JwtInvalidClaimError {}

const verifier = CognitoJwtVerifier.create({
  userPoolId: "<user_pool_id>",
  tokenUse: "access",
  clientId: "<client_id>",
  includeRawJwtInErrors: true,
  customJwtCheck: ({ payload }) => {
    if (payload.custom_claim !== "expected")
      throw new CustomError("Invalid JWT", payload.custom_claim, "expected");
  },
});

try {
  const payload = await verifier.verify(
    "eyJraWQeyJhdF9oYXNoIjoidk..." // the JWT as string
  );
} catch (err) {
  if (err instanceof JwtInvalidClaimError) {
    console.error("JWT invalid:", err.rawJwt.payload);
  }
  throw new Error("Unauthorized");
}
```

## The JWKS cache

The JWKS cache is responsible for fetching the JWKS from the JWKS URI, caching it, and selecting the right JWK from it. Both the `CognitoJwtVerifier` and the (generic) `JwtRsaVerifier` utilize an in-memory JWKS cache. For each `issuer` a JWKS cache is maintained, and each JWK in a JWKS is selected and cached using its `kid` (key id). The JWKS for an `issuer` will be fetched once initially, and thereafter only upon key rotations (detected by the occurrence of a JWT with a `kid` that is not yet in the cache).

Note: examples below work the same for `CognitoJwtVerifier` and `JwtRsaVerifier`.

### Loading the JWKS from file

If e.g. your runtime environment doesn't have internet access, or you want to prevent the fetch over the network, you can load the JWKS explicitly yourself:

```typescript
import { CognitoJwtVerifier } from "aws-jwt-verify";
import { readFileSync } from "fs";

const idTokenVerifier = CognitoJwtVerifier.create({
  userPoolId: "<user_pool_id>",
  tokenUse: "id",
  clientId: "<client_id>",
});

const jwks = JSON.parse(readFileSync("jwks.json", { encoding: "utf-8" }));
idTokenVerifier.cacheJwks(jwks);

// Because the JWKS doesn't need to be downloaded now, you can use verifySync:
try {
  const idTokenPayload = idTokenVerifier.verifySync(
    "eyJraWQeyJhdF9oYXNoIjoidk..."
  );
  console.log("Token is valid. Payload:", payload);
} catch {
  console.log("Token not valid!");
}

// Async verify will of course work as well (and will use the cache also):
try {
  const idTokenPayload = await idTokenVerifier.verify(
    "eyJraWQeyJhdF9oYXNoIjoidk..."
  );
  console.log("Token is valid. Payload:", idTokenPayload);
} catch {
  console.log("Token not valid!");
}
```

Note that the verifier will still try to fetch the JWKS, if it encounters a JWT with a kid that is not in it's cached JWKS (i.e. to cater for key rotations).

### Rate limiting

Both the `CognitoJwtVerifier` and the `JwtRsaVerifier` enforce a rate limit of 1 JWKS download per JWKS uri per 10 seconds. This protects users of this library from inadvertently flooding the JWKS uri with requests, and prevents wasting time doing network calls.

The rate limit works as follows (implemented by the `penaltyBox`, see below). When the verifier fetches the JWKS and fails to locate the JWT's kid in the JWKS, an error is thrown, and a timer of 10 seconds is started. Until that timer completes, the verifier will refuse to fetch the particular JWKS uri again. It will instead throw an error immediately on `verify` calls where that would require the JWKS to be downloaded.

The verifier will continue to verify JWTs for which the right JWK is already present in the cache, also it will still try other JWKS uris (for other issuers).

It is possible to implement a different rate limiting scheme yourself, by customizing the JWKS cache, or the `penaltyBox` implementation, see below.

### Explicitly hydrating the JWKS cache

In a long running Node.js API (e.g. a Fargate container), it might make sense to hydrate the JWKS cache upon server start up. This will speed up the first JWT verification, as the JWKS doesn't have to be downloaded anymore.

This call will always fetch the current, latest, JWKS for each of the verifier's issuers (even though the JWKS might have been fetched and cached before):

```typescript
const verifier = JwtRsaVerifier.create([
  {
    issuer: "https://example.com/idp1",
    audience: "myappclient1",
  },
  {
    issuer: "https://example.com/idp2",
    audience: "myappclient2",
  },
]);

// Fetch and cache the JWKS for all configured issuers
await verifier.hydrate();
```

Note: it is only useful to call this method if your calling process has an idle time window, in which it might just as well fetch the JWKS. For example, during container start up, when the load balancer does not yet route traffic to the container. Calling this method inside API Gateway custom authorizers or Lambda@Edge has no benefit (in fact, awaiting the call as part of the Lambda handler would even hurt performance as it bypasses the existing cached JWKS).

### Clearing the JWKS cache

If you have a predefined rotation schedule for your JWKS, you could set the refresh interval of the verifier aligned to this schedule:

```typescript
import { JwtRsaVerifier } from "aws-jwt-verify";

const verifier = JwtRsaVerifier.create({
  issuer: "https://example.com/",
  audience: "<audience>",
});

setInterval(() => {
  verifier.cacheJwks({ keys: [] }); // empty cache, by loading an empty JWKS
}, 1000 * 60 * 60 * 4); // For a 4 hour refresh schedule
```

If an automated rotation does not fit your use case, and you need to clear out the JWKS cache, you could use:

```typescript
verifier.cacheJwks({ keys: [] });
```

### Customizing the JWKS cache

When you instantiate a `CognitoJwtVerifier` or `JwtRsaVerifier` without providing a `JwksCache`, the `SimpleJwksCache` is used:

```typescript
import { JwtRsaVerifier } from "aws-jwt-verify";
import { SimpleJwksCache } from "aws-jwt-verify/jwk";

const verifier = JwtRsaVerifier.create({
  issuer: "http://my-tenant.my-idp.com",
});

// Equivalent:
const verifier2 = JwtRsaVerifier.create(
  {
    issuer: "http://my-tenant.my-idp.com",
  },
  {
    jwksCache: new SimpleJwksCache(),
  }
);
```

The `SimpleJwksCache` can be tailored by using a different `penaltyBox` and/or `fetcher` (see below).

Alternatively, you can implement an entirely custom `JwksCache` yourself, by creating a class that implements the interface `JwksCache` (from `"aws-jwt-verify/jwk"`). This allows for highly custom scenario's, e.g. you could implement a `JwksCache` with custom logic for selecting a JWK from the JWKS.

### Sharing the JWKS cache amongst different verifiers

If you want to define multiple verifiers for the same JWKS uri, it makes sense to share the JWKS cache, so the JWKS will be downloaded and cached once:

```typescript
import { JwtRsaVerifier } from "aws-jwt-verify";
import { SimpleJwksCache } from "aws-jwt-verify/jwk";

const sharedJwksCache = new SimpleJwksCache();

const verifierA = JwtRsaVerifier.create(
  {
    jwksUri: "https://example.com/keys/jwks.json",
    issuer: "https://example.com/",
    audience: "<audience>",
  },
  {
    jwksCache: sharedJwksCache,
  }
);

const verifierB = JwtRsaVerifier.create(
  {
    jwksUri: "https://example.com/keys/jwks.json", // same JWKS URI, so sharing cache makes sense
    issuer: "https://example.com/",
    audience: "<audience>",
  },
  {
    jwksCache: sharedJwksCache,
  }
);
```

### Using a different `JsonFetcher` with `SimpleJwksCache`

When instantiating `SimpleJwksCache`, the `fetcher` property can be populated with an instance of a class that implements the interface `JsonFetcher` (from `"aws-jwt-verify/https"`), such as the `SimpleJsonFetcher` (which is the default).

The purpose of the fetcher, is to execute fetches against the JWKS uri (HTTPS GET) and parse the resulting JSON file.
The default implementation, the `SimpleJsonFetcher`, has basic machinery to do fetches over HTTPS. It does 1 (immediate) retry in case of connection errors.

By supplying a custom fetcher when instantiating `SimpleJwksCache`, instead of `SimpleJsonFetcher`, you can implement any retry and backoff scheme you want, or use another HTTPS library:

```typescript
import { JwtRsaVerifier } from "aws-jwt-verify";
import { SimpleJwksCache } from "aws-jwt-verify/jwk";
import { JsonFetcher } from "aws-jwt-verify/https";
import axios from "axios";

// Use axios to do the HTTPS fetches
class CustomFetcher implements JsonFetcher {
  instance = axios.create();
  public async fetch(uri: string) {
    return this.instance.get(uri).then((response) => response.data);
  }
}

const verifier = JwtRsaVerifier.create(
  {
    issuer: "http://my-tenant.my-idp.com",
  },
  {
    jwksCache: new SimpleJwksCache({
      fetcher: new CustomFetcher(),
    }),
  }
);
```

### Configuring the JWKS response timeout and other HTTP options with `JsonFetcher`

The following configurations are equivalent, use the latter one to set a custom fetch timeout and other HTTP options.

```typescript
import { CognitoJwtVerifier } from "aws-jwt-verify";

// No jwksCache configured explicitly,
// so the default `SimpleJwksCache` with `SimpleJsonFetcher` will be used,
// with a default response timeout of 1500 ms.:
const verifier = CognitoJwtVerifier.create({
  userPoolId: "<user_pool_id>",
  tokenUse: "access", // or "id"
  clientId: "<client_id>",
});
```

Equivalent explicit configuration:

```typescript
import { CognitoJwtVerifier } from "aws-jwt-verify";
import { SimpleJwksCache } from "aws-jwt-verify/jwk";
import { SimpleJsonFetcher } from "aws-jwt-verify/https";

const verifier = CognitoJwtVerifier.create(
  {
    userPoolId: "<your user pool id>",
    tokenUse: "access", // or "id",
    clientId: "<your client id>",
  },
  {
    jwksCache: new SimpleJwksCache({
      fetcher: new SimpleJsonFetcher({
        defaultRequestOptions: {
          responseTimeout: 1500,
          // You can add additional request options:
          // For NodeJS: https://nodejs.org/api/http.html#httprequestoptions-callback
          // For Web (init object): https://developer.mozilla.org/en-US/docs/Web/API/fetch#syntax
        },
      }),
    }),
  }
);
```

### Using a different `penaltyBox` with `SimpleJwksCache`

When instantiating `SimpleJwksCache`, the `penaltyBox` property can be populated with an instance of a class that implements the interface `PenaltyBox` (from `"aws-jwt-verify/jwk"`), such as the `SimplePenaltyBox` (which is the default).

The `SimpleJwksCache` will always do `await penaltyBox.wait(jwksUri, kid)` before asking the `fetcher` to fetch the JWKS.

By supplying a custom penaltyBox when instantiating `SimpleJwksCache`, instead of `SimplePenaltyBox`, you can implement any waiting scheme you want, in your implementation of the `wait` function.

The `SimpleJwksCache` will call `penaltyBox.registerSuccessfulAttempt(jwksUri, kid)` when it succeeds in locating the right JWK in the JWKS, and call `penaltyBox.registerFailedAttempt(jwksUri, kid)` otherwise. You need to process these calls, so that you can determine the right amount of waiting in your `wait` implementation.

```typescript
import { JwtRsaVerifier } from "aws-jwt-verify";
import {
  SimpleJwksCache,
  SimplePenaltyBox,
  PenaltyBox,
} from "aws-jwt-verify/jwk";

// In this example we use the SimplePenaltyBox, but override the default wait period
const verifier = JwtRsaVerifier.create(
  {
    issuer: "http://my-tenant.my-idp.com",
  },
  {
    jwksCache: new SimpleJwksCache({
      penaltyBox: new SimplePenaltyBox({ waitSeconds: 1 }),
    }),
  }
);

// Or implement your own penaltyBox
// The example here just stupidly waits 5 second always,
// even on the first fetch of the JWKS uri
class CustomPenaltyBox implements PenaltyBox {
  public async wait(jwksUri: string, kid: string) {
    // implement something better
    await new Promise((resolve) => setTimeout(resolve, 5000));
  }
  public registerFailedAttempt(jwksUri: string, kid: string) {
    // implement
  }
  public registerSuccessfulAttempt(jwksUri: string, kid: string) {
    // implement
  }
}
const verifier2 = JwtRsaVerifier.create(
  {
    issuer: "http://my-tenant.my-idp.com",
  },
  {
    jwksCache: new SimpleJwksCache({ penaltyBox: new CustomPenaltyBox() }),
  }
);
```

## Usage Examples

### CloudFront Lambda@Edge

The verifier should be instantiated _outside_ the Lambda handler, so the verifier's cache can be reused for subsequent requests for as long as the Lambda functions stays "hot".

This is an example of a [Viewer Request Lambda@Edge](https://docs.aws.amazon.com/lambda/latest/dg/lambda-edge.html) function, that inspects each incoming request. It requires each incoming request to have a valid JWT (in this case an access token that includes scope "read") in the HTTP "Authorization" header.

```javascript
const { CognitoJwtVerifier } = require("aws-jwt-verify");

// Create the verifier outside the Lambda handler (= during cold start),
// so the cache can be reused for subsequent invocations. Then, only during the
// first invocation, will the verifier actually need to fetch the JWKS.
const jwtVerifier = CognitoJwtVerifier.create({
  userPoolId: "<user_pool_id>",
  tokenUse: "access",
  clientId: "<client_id>",
  scope: "read",
});

exports.handler = async (event) => {
  const { request } = event.Records[0].cf;
  const accessToken = request.headers["authorization"][0].value;
  try {
    await jwtVerifier.verify(accessToken);
  } catch {
    return {
      status: "403",
      body: "Unauthorized",
    };
  }
  return request; // allow request to proceed
};
```

### API Gateway Lambda Authorizer - REST

The verifier should be instantiated _outside_ the Lambda handler, so the verifier's cache can be reused for subsequent requests for as long as the Lambda functions stays "hot".

Two types of API Gateway Lambda authorizers could be created - token based and request-based. For both the types of authorizers, you could use the [AWS API Gateway Lambda Authorizer BluePrint](https://github.com/awslabs/aws-apigateway-lambda-authorizer-blueprints/blob/master/blueprints/nodejs/index.js) as a reference pattern where the [token validation](https://github.com/awslabs/aws-apigateway-lambda-authorizer-blueprints/blob/master/blueprints/nodejs/index.js#L17) could be achieved as follows

For token based authorizers, where lambda event payload is set to `Token` and token source is set to (http) `Header` with name `authorization`:

```javascript
const { CognitoJwtVerifier } = require("aws-jwt-verify");

// Create the verifier outside the Lambda handler (= during cold start),
// so the cache can be reused for subsequent invocations. Then, only during the
// first invocation, will the verifier actually need to fetch the JWKS.
const jwtVerifier = CognitoJwtVerifier.create({
  userPoolId: "<user_pool_id>",
  tokenUse: "access",
  clientId: "<client_id>",
  scope: "read",
});

exports.handler = async (event) => {
  const accessToken = event.authorizationToken;

  let payload;
  try {
    // If the token is not valid, an error is thrown:
    payload = await jwtVerifier.verify(accessToken);
  } catch {
    // API Gateway wants this *exact* error message, otherwise it returns 500 instead of 401:
    throw new Error("Unauthorized");
  }

  // Proceed with additional authorization logic
  // ...
};
```

For request based authorizers, where lambda event payload is set to `Request` and identity source is set to (http) `Header` with name `authorization`:

```javascript
const { CognitoJwtVerifier } = require("aws-jwt-verify");

// Create the verifier outside the Lambda handler (= during cold start),
// so the cache can be reused for subsequent invocations. Then, only during the
// first invocation, will the verifier actually need to fetch the JWKS.
const jwtVerifier = CognitoJwtVerifier.create({
  userPoolId: "<user_pool_id>",
  tokenUse: "access",
  clientId: "<client_id>",
  scope: "read",
});

exports.handler = async (event) => {
  const accessToken = event.headers["authorization"];

  let payload;
  try {
    // If the token is not valid, an error is thrown:
    payload = await jwtVerifier.verify(accessToken);
  } catch {
    // API Gateway wants this *exact* error message, otherwise it returns 500 instead of 401:
    throw new Error("Unauthorized");
  }

  // Proceed with additional authorization logic
  // ...
};
```

### HTTP API Lambda Authorizer

An example of a sample HTTP Lambda authorizer is included [here](tests/cognito/lib/lambda-authorizer/index.js) as part of the test suite for the solution ([format 2.0](https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-lambda-authorizer.html#http-api-lambda-authorizer.payload-format-response)).

### AppSync Lambda Authorizer

The verifier should be instantiated _outside_ the Lambda handler, so the verifier's cache can be reused for subsequent requests for as long as the Lambda functions stays "hot".

This is an example of [AppSync Lambda Authorization](https://docs.aws.amazon.com/appsync/latest/devguide/security-authz.html#aws-lambda-authorization) function, that validates the JWT is valid (in this case an access token that includes scope "read") along with other authorization business logic

```javascript
const { CognitoJwtVerifier } = require("aws-jwt-verify");

// Create the verifier outside the Lambda handler (= during cold start),
// so the cache can be reused for subsequent invocations. Then, only during the
// first invocation, will the verifier actually need to fetch the JWKS.
const jwtVerifier = CognitoJwtVerifier.create({
  userPoolId: "<user_pool_id>",
  tokenUse: "access",
  clientId: "<client_id>",
  scope: "read",
});

exports.handler = async (event) => {
  const accessToken = event.authorizationToken;
  try {
    await jwtVerifier.verify(accessToken);
  } catch {
    return {
      isAuthorized: false,
    };
  }
  //Proceed with additional authorization logic
};
```

### Fastify

```javascript
const { CognitoJwtVerifier } = require("aws-jwt-verify");
const fastify = require("fastify")({ logger: true });

// Create the verifier outside your route handlers,
// so the cache is persisted and can be shared amongst them.
const jwtVerifier = CognitoJwtVerifier.create({
  userPoolId: "<user_pool_id>",
  tokenUse: "access",
  clientId: "<client_id>",
  scope: "read",
});

fastify.get("/", async (request, reply) => {
  try {
    // A valid JWT is expected in the HTTP header "authorization"
    await jwtVerifier.verify(request.headers.authorization);
  } catch (authErr) {
    fastify.log.error(authErr);
    const err = new Error();
    err.statusCode = 403;
    throw err;
  }
  return { private: "only visible to users sending a valid JWT" };
});

const startFastify = async () => {
  try {
    await fastify.listen(3000);
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
};

// Hydrate the JWT verifier, and start Fastify.
// Hydrating the verifier makes sure the JWKS is loaded into the JWT verifier,
// so it can verify JWTs immediately without any latency.
// (Alternatively, just start Fastify, the JWKS will be downloaded when the first JWT is being verified then)
Promise.all([jwtVerifier.hydrate(), () => fastify.listen(3000)]).catch(
  (err) => {
    fastify.log.error(err);
    process.exit(1);
  }
);
```

### Express

```javascript
const { CognitoJwtVerifier } = require("aws-jwt-verify");
const express = require("express");
const app = express();
const port = 3000;

// Create the verifier outside your route handlers,
// so the cache is persisted and can be shared amongst them.
const jwtVerifier = CognitoJwtVerifier.create({
  userPoolId: "<user_pool_id>",
  tokenUse: "access",
  clientId: "<client_id>",
  scope: "read",
});

app.get("/", async (req, res, next) => {
  try {
    // A valid JWT is expected in the HTTP header "authorization"
    await jwtVerifier.verify(req.header("authorization"));
  } catch (err) {
    console.error(err);
    return res.status(403).json({ statusCode: 403, message: "Forbidden" });
  }
  res.json({ private: "only visible to users sending a valid JWT" });
});

// Hydrate the JWT verifier, then start express.
// Hydrating the verifier makes sure the JWKS is loaded into the JWT verifier,
// so it can verify JWTs immediately without any latency.
// (Alternatively, just start express, the JWKS will be downloaded when the first JWT is being verified then)
jwtVerifier
  .hydrate()
  .catch((err) => {
    console.error(`Failed to hydrate JWT verifier: ${err}`);
    process.exit(1);
  })
  .then(() =>
    app.listen(port, () => {
      console.log(`Example app listening at http://localhost:${port}`);
    })
  );
```

# Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

# License

This project is licensed under the Apache-2.0 License.
