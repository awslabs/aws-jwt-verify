# AWS JWT Verify

**JavaScript** library for **verifying** JWTs signed by **Amazon Cognito**, **Application Load Balancer**, and any **OIDC-compatible IDP**.

## Installation

`npm install aws-jwt-verify`

This library can be used with Node.js 18 or higher. If used with TypeScript, TypeScript 4 or higher is required.

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
import { JwtVerifier } from "aws-jwt-verify";

const verifier = JwtVerifier.create({
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

See all verify parameters for JWTs from any IDP [here](#JwtVerifier-verify-parameters).

### Non-standard IDPs

To make special cases work, you can use lower level constructs directly:

```typescript
import { verifyJwt } from "aws-jwt-verify/jwt-verifier"; // there is also verifyJwtSync() for if you already have the JWK(S) at hand
import { SimpleJwksCache } from "aws-jwt-verify/jwk";

// E.g. use SimpleJwksCache to fetch and cache JSON Web Key Sets (JWKS)
// SimpleJwksCache will deal with key rotations automatically
const jwksCache = new SimpleJwksCache();

try {
  const payload = await verifyJwt(
    "eyJraWQeyJhdF9oYXNoIjoidk...", // the JWT as string
    "https://example.com/.well-known/jwks.json", // set this to the JWKS uri from your OpenID configuration
    {
      issuer: "<iss>", // set this to the expected iss claim on the JWT (or to null, to skip this check)
      audience: "<aud>", // set this to the expected aud claim on the JWT (or to null, to skip this check)
    },
    jwksCache.getJwk.bind(jwksCache) // use JWKS cache (optional)
  );
  console.log("Token is valid. Payload:", payload);
} catch {
  console.log("Token not valid!");
}
```

### Application Load Balancer

When the [Application Load Balancer authentication feature at listener level](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/listener-authenticate-users.html) is enabled, 2 JWTs tokens are forwarded via the HTTP header:

- `x-amzn-oidc-accesstoken`: access token signed by Cognito or another IDP
- `x-amzn-oidc-data`: user claims JWT signed by the ALB

The access token can be verified directly with `CognitoJwtVerifier` or `JwtVerifier` like in examples above, depending on the ALB authentication configuration.

The user claims token can be verified by the `AlbJwtVerifier` like in the code example below:

```typescript
import { AlbJwtVerifier } from "aws-jwt-verify";

// Verifier that expects valid access tokens:
const verifier = AlbJwtVerifier.create({
  albArn: "<alb_arn>",
  issuer: "<issuer>", // set this to the expected "iss" claim on your JWTs
  clientId: "<client_id>", // set this to the expected "client" claim on your JWTs
});

try {
  const payload = await verifier.verify(
    "eyJraWQeyJhdF9oYXNoIjoidk..." // the user claims JWT as string, provided in the x-amzn-oidc-data HTTP header
  );
  console.log("Token is valid. Payload:", payload);
} catch {
  console.log("Token not valid!");
}
```

See all verify parameters for Amazon Application Load Balancer JWTs [here](#albjwtverifier-verify-parameters).

## Philosophy of this library

- Do one thing and do it well. Focus solely on **verifying** JWTs.
- Pure **TypeScript** library that can be used in **Node.js** v18 and above (both CommonJS and ESM supported), as well in the modern evergreen Web browser.
- Support both **Amazon Cognito** as well as any other **OIDC-compatible IDP** as first class citizen.
- **0** runtime dependencies, batteries included. This library includes all necessary code to verify JWTs. E.g. it contains a simple (and pluggable) **HTTP** helper to fetch the **JWKS** from the JWKS URI.
- Opinionated towards the **best practices** as described by the IETF in [JSON Web Token Best Current Practices](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-jwt-bcp-02#section-3).
- Make it **easy** for users to use this library in a **secure** way. For example, this library requires users to specify `issuer` and `audience`, as these should be checked for (see best practices linked to above). Standard claims, such as `exp` and `nbf`, are checked automatically.

Currently, the following signature algorithms are supported:

- **`RS256` (RSA)**
- **`RS384` (RSA)**
- **`RS512` (RSA)**
- **`ES256` (ECDSA)**
- **`ES384` (ECDSA)**
- **`ES512` (ECDSA)**
- **`Ed25519` (EdDSA)**
- **`Ed448` (EdDSA)**

Please leave us a GitHub issue if you need another algorithm.

## Intended Usage

This library was specifically designed to be easy to use in:

- [API Gateway Lambda authorizers](#api-gateway-lambda-authorizer---rest)
- [AppSync Lambda authorizers](#appsync-lambda-authorizer)
- [CloudFront Lambda@Edge](#cloudfront-lambdaedge)
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
  - [Using the generic JWT verifier for Cognito JWTs](#using-the-generic-jwt-verifier-for-cognito-jwts)
- [Verifying JWTs from any OIDC-compatible IDP](#verifying-jwts-from-any-oidc-compatible-idp)
  - [Verify parameters](#JwtVerifier-verify-parameters)
- [Verifying user claims JWTs from Application Load Balancers](#verifying-user-claims-jwts-from-application-load-balancers)
  - [Verify parameters](#albjwtverifier-verify-parameters)
  - [Trusting multiple User Pools](#trusting-multiple-application-load-balancers)
- [How the algorithm (`alg`) is selected to verify the JWT signature with](#how-the-algorithm-alg-is-selected-to-verify-the-jwt-signature-with)
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
  - [Using a different `Fetcher` with `SimpleJwksCache`](#using-a-different-fetcher-with-simplejwkscache)
  - [Configuring the JWKS response timeout and other HTTP options with `Fetcher`](#configuring-the-jwks-response-timeout-and-other-http-options-with-fetcher)
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

- `userPoolId` (mandatory): the Cognito User Pool ID. The issuer (`iss`) and `jwksUri` will be determined from this.
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

### Using the generic JWT verifier for Cognito JWTs

The generic `JwtVerifier` (see [below](#verifying-jwts-from-any-oidc-compatible-idp)) can also be used for Cognito, which is useful if you want to define a verifier that trusts multiple IDPs, i.e. Cognito and another IDP.

In this case, leave `audience` to `null`, but rather manually add `validateCognitoJwtFields` in the `customJwtCheck`.
(Only Cognito ID tokens have an `audience` claim, Cognito Access token have a `client_id` claim instead. The `validateCognitoJwtFields` function handles this difference automatically for you)

```typescript
import { JwtVerifier } from "aws-jwt-verify";
import { validateCognitoJwtFields } from "aws-jwt-verify/cognito-verifier";

const verifier = JwtVerifier.create([
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

The generic `JwtVerifier` works for any OIDC-compatible IDP:

```typescript
import { JwtVerifier } from "aws-jwt-verify";

const verifier = JwtVerifier.create({
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
const verifier = JwtVerifier.create([
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

### `JwtVerifier` `verify` parameters

Except `issuer`, parameters provided when creating the `JwtVerifier` act as defaults, that can be overridden upon calling `verify` or `verifySync`.

Supported parameters are:

- `issuer` (mandatory): set this to the expected `iss` claim on the JWTs. Provide a single string, or set to `null` to skip checking issuer (not recommended unless you know what you are doing).
- `jwksUri` (optional, can only be provided at verifier level): the URI where the JWKS can be downloaded from. To find this URI for your IDP, consult your IDP's OpenId configuration (e.g. by opening the OpenId configuration in your browser). Usually, it is `${issuer}/.well-known/jwks.json`, which is the default value that will be used if you don't explicitly provide `jwksUri`.
- `audience` (mandatory): verify that the JWT's `aud` claim matches your expectation. Provide a string, or an array of strings to allow multiple client ids (i.e. one of these audiences must match the JWT). Set to `null` to skip checking audience (not recommended unless you know what you are doing). Note that a JWT's `aud` claim might be an array of audiences. The `JwtVerifier` will in that case make sure that at least one of these audiences matches with at least one of the audiences that were provided to the verifier.
- `scope` (optional): verify that the JWT's `scope` claim matches your expectation (only of use for access tokens). Provide a string, or an array of strings to allow multiple scopes (i.e. one of these scopes must match the JWT). See also [Checking scope](#checking-scope).
- `graceSeconds` (optional, default `0`): to account for clock differences between systems, provide the number of seconds beyond JWT expiry (`exp` claim) or before "not before" (`nbf` claim) you will allow.
- `customJwtCheck` (optional): your custom function with additional JWT checks to execute (see [Custom JWT and JWK checks](#custom-jwt-and-jwk-checks)).
- `includeRawJwtInErrors` (optional, default `false`): set to `true` if you want to peek inside the invalid JWT when verification fails. Refer to: [Peek inside invalid JWTs](#peek-inside-invalid-jwts).

## Verifying user claims JWTs from Application Load Balancers

The generic `JwtVerifier` can verify user claims JWTs provided by Application Load Balancers with [authentication feature enabled](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/listener-authenticate-users.html). This token is present in the HTTP header `x-amzn-oidc-data` forwarded by the Application Load Balancer to the backend.

### `AlbJwtVerifier` `verify` parameters

Except `albArn` and `issuer`, parameters provided when creating the `AlbJwtVerifier` act as defaults, that can be overridden upon calling `verify` or `verifySync`.

Supported parameters are:

- `albArn` (mandatory): the Application Load Balancer ARN sending the user claims JWT to verify.
- `issuer` (mandatory): set this to the expected `iss` claim on the JWTs. Provide a single string, or set to `null` to skip checking issuer (not recommended unless you know what you are doing). If the ALB listener authentication is configured with cognito as the IDP, this parameter should be `https://cognito-idp.${region}.amazonaws.com/${userPoolId}`.
- `jwksUri` (optional, default `https://public-keys.auth.elb.${region}.amazonaws.com`): the ALB public key FQDN. For the default value, the region is automatically extracted from the `albArn`. If the application is hosted on the AWS GovCloud (US), this parameter needs to be specified with one of these values: `https://s3-us-gov-west-1.amazonaws.com/aws-elb-public-keys-prod-us-gov-west-1` or `https://s3-us-gov-east-1.amazonaws.com/aws-elb-public-keys-prod-us-gov-east-1` depending on the region.
- `clientId` (mandatory): verify that the JWT's `client_id` claim matches your expectation. Provide a string, or an array of strings to allow multiple client ids (i.e. one of these client ids must match the JWT). Set to `null` to skip checking client id (not recommended unless you know what you are doing).
- `graceSeconds` (optional, default `0`): to account for clock differences between systems, provide the number of seconds beyond JWT expiry (`exp` claim) or before "not before" (`nbf` claim) you will allow.
- `customJwtCheck` (optional): your custom function with additional JWT (and JWK) checks to execute (see also below).
- `includeRawJwtInErrors` (optional, default `false`): set to `true` if you want to peek inside the invalid JWT when verification fails. Refer to: [Peek inside invalid JWTs](#peek-inside-invalid-jwts).

```typescript
import { AlbJwtVerifier } from "aws-jwt-verify";

const verifier = AlbJwtVerifier.create({
  albArn: "<alb_arn>",
  issuer: "<issuer>",
  clientId: "<client_id>", // needs to be specified here or upon calling verify
  graceSeconds: 0, // optional
  customJwtCheck: (payload, header, jwk) => {}, // optional
});

try {
  const payload = await verifier.verify("eyJraWQeyJhdF9oYXNoIjoidk...");
  console.log("Token is valid. Payload:", payload);
} catch {
  console.log("Token not valid!");
}
```

### Trusting multiple Application Load Balancers

If you want to allow JWTs from multiple Application Load Balancers with different issuers, provide an array of configuration objects upon creating the verifier (each distinct issuer must be represented in a separate configuration object):

```typescript
import { AlbJwtVerifier } from "aws-jwt-verify";

// This verifier will trust both Application Load Balancers
const idTokenVerifier = AlbJwtVerifier.create([
  {
    albArn: "<alb_arn_1>",
    issuer: "<issuer_1>",
    clientId: "<client_id_1>",
  },
  {
    albArn: "<alb_arn_2>",
    issuer: "<issuer_2>",
    clientId: "<client_id_2>",
  },
]);

try {
  const idTokenPayload = await idTokenVerifier.verify(
    "eyJraWQeyJhdF9oYXNoIjoidk..." // token must be signed by either of the Application Load Balancer
  );
  console.log("Token is valid. Payload:", idTokenPayload);
} catch {
  console.log("Token not valid!");
}
```

If you're using multiple Application Load Balancers with the same IDP (same Amazon Cognito User Pool or same IDP issuer), pass an array of `albArn` (each distinct issuer must be represented in only one configuration object):

```typescript
import { AlbJwtVerifier } from "aws-jwt-verify";

// This verifier will trust both Application Load Balancers
const idTokenVerifier = AlbJwtVerifier.create({
  albArn: ["<alb_arn_1>", "<alb_arn_2>"],
  issuer: "<issuer>",
  clientId: "<client_id>",
});

try {
  const idTokenPayload = await idTokenVerifier.verify(
    "eyJraWQeyJhdF9oYXNoIjoidk..." // token must be signed by either of the Application Load Balancer
  );
  console.log("Token is valid. Payload:", idTokenPayload);
} catch {
  console.log("Token not valid!");
}
```

## How the algorithm (`alg`) is selected to verify the JWT signature with

`aws-jwt-verify` does not require users to specify the algorithm (`alg`) to verify JWT signatures with. Rather, the `alg` is selected automatically from the JWT header, and matched against the `alg` (if any) on the selected JWK. We believe this design decision makes it easier to use this library: one less parameter to provide, that developers potentially would not know which value to provide for.

To readers who are intimately aware of how JWT verification in general should work, this design decision may seem dubious, because the JWT header, and thus the `alg` in it, would be under potential threat actor control. But this is mitigated because `aws-jwt-verify` only allows a limited set of algorithms anyway, all asymmetric (see [above](#philosophy-of-this-library)). The egregious case of `alg` with value `none` is explicitly not supported, nor are symmetric algorithms, and such JWTs would be considered invalid.

If the JWK that's selected for verification (see [The JWKS cache](#the-jwks-cache)) has an `alg`, it must match the JWT header's `alg`, or the JWT is considered invalid. `alg` is an optional JWK field, but in practice present in most implementations (such as Amazon Cognito User Pools).

### Advanced: enforcing the algorithm (`alg`)

If you really want to enforce a certain `alg`, you should use a JWKS that only contains JWKs which have that `alg` explicitly specified.

If the JWKS is not under your control, you can customize the way your JWKS is used by [customizing the JWKS cache](#customizing-the-jwks-cache). E.g. you could explicitly set the `alg` value on each JWK, or filter the JWKS to only those JWKs that have a specific `alg`, such as in the example below:

```typescript
import { CognitoJwtVerifier } from "aws-jwt-verify";
import { SimpleJwksCache } from "aws-jwt-verify/jwk";

class Rs256OnlyJwksCache extends SimpleJwksCache {
  async getJwks(jwksUri: string) {
    const jwks = await super.getJwks(jwksUri);
    // filter JWKS to RS256 only
    jwks.keys = jwks.keys.filter((jwk) => jwk.alg === "RS256");
    return jwks;
  }
}

const verifier = CognitoJwtVerifier.create(
  {
    userPoolId: "<user_pool_id>",
    tokenUse: "access",
    clientId: "<client_id>",
  },
  {
    jwksCache: new Rs256OnlyJwksCache(),
  }
);
```

Alternatively, you can code a [custom JWT check](#custom-jwt-and-jwk-checks) to enforce that the JWT's header `alg` value matches the `alg` you want to enforce.

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
- Stage 2: Verify JWT cryptographic signature (e.g. with algorithm ES256)
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

The JWKS cache is responsible for fetching the JWKS from the JWKS URI, caching it, and selecting the right JWK from it. Both the `CognitoJwtVerifier` and the (generic) `JwtVerifier` utilize an in-memory JWKS cache. For each `issuer` a JWKS cache is maintained, and each JWK in a JWKS is selected and cached using its `kid` (key id). The JWKS for an `issuer` will be fetched once initially, and thereafter only upon key rotations (detected by the occurrence of a JWT with a `kid` that is not yet in the cache).

Note: examples below work the same for `CognitoJwtVerifier` and `JwtVerifier`.

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

Both the `CognitoJwtVerifier` and the `JwtVerifier` enforce a rate limit of 1 JWKS download per JWKS uri per 10 seconds. This protects users of this library from inadvertently flooding the JWKS uri with requests, and prevents wasting time doing network calls.

The rate limit works as follows (implemented by the `penaltyBox`, see below). When the verifier fetches the JWKS and fails to locate the JWT's kid in the JWKS, an error is thrown, and a timer of 10 seconds is started. Until that timer completes, the verifier will refuse to fetch the particular JWKS uri again. It will instead throw an error immediately on `verify` calls where that would require the JWKS to be downloaded.

The verifier will continue to verify JWTs for which the right JWK is already present in the cache, also it will still try other JWKS uris (for other issuers).

It is possible to implement a different rate limiting scheme yourself, by customizing the JWKS cache, or the `penaltyBox` implementation, see below.

### Explicitly hydrating the JWKS cache

In a long running Node.js API (e.g. a Fargate container), it might make sense to hydrate the JWKS cache upon server start up. This will speed up the first JWT verification, as the JWKS doesn't have to be downloaded anymore.

This call will always fetch the current, latest, JWKS for each of the verifier's issuers (even though the JWKS might have been fetched and cached before):

```typescript
const verifier = JwtVerifier.create([
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

Note: it is only useful to call this method if your calling process has a time window, in which it might just as well fetch the JWKS. For example, during container start up, when the load balancer does not yet route traffic to the container. Calling this method in AWS Lambda functions only makes sense if you do it outside the Lambda handler, i.e. with a top-level await that is part of the code that runs during "cold starts". Awaiting `verifier.hydrate()` inside the Lambda handler will hurt performance as it always bypasses the existing cached JWKS.

### Clearing the JWKS cache

If you have a predefined rotation schedule for your JWKS, you could set the refresh interval of the verifier aligned to this schedule:

```typescript
import { JwtVerifier } from "aws-jwt-verify";

const verifier = JwtVerifier.create({
  issuer: "https://example.com/",
  audience: "<audience>",
});

setInterval(
  () => {
    verifier.cacheJwks({ keys: [] }); // empty cache, by loading an empty JWKS
  },
  1000 * 60 * 60 * 4
); // For a 4 hour refresh schedule
```

If an automated rotation does not fit your use case, and you need to clear out the JWKS cache, you could use:

```typescript
verifier.cacheJwks({ keys: [] });
```

### Customizing the JWKS cache

When you instantiate a `CognitoJwtVerifier` or `JwtVerifier` without providing a `JwksCache`, the `SimpleJwksCache` is used:

```typescript
import { JwtVerifier } from "aws-jwt-verify";
import { SimpleJwksCache } from "aws-jwt-verify/jwk";

const verifier = JwtVerifier.create({
  issuer: "http://my-tenant.my-idp.com",
});

// Equivalent:
const verifier2 = JwtVerifier.create(
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
import { JwtVerifier } from "aws-jwt-verify";
import { SimpleJwksCache } from "aws-jwt-verify/jwk";

const sharedJwksCache = new SimpleJwksCache();

const verifierA = JwtVerifier.create(
  {
    jwksUri: "https://example.com/keys/jwks.json",
    issuer: "https://example.com/",
    audience: "<audience>",
  },
  {
    jwksCache: sharedJwksCache,
  }
);

const verifierB = JwtVerifier.create(
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

### Using a different `Fetcher` with `SimpleJwksCache`

When instantiating `SimpleJwksCache`, the `fetcher` property can be populated with an instance of a class that implements the interface `Fetcher` (from `"aws-jwt-verify/https"`), such as the `SimpleFetcher` (which is the default).

The purpose of the fetcher, is to execute fetches against the JWKS uri (HTTPS GET) and return the response as an arraybuffer (that will be UTF-8 decoded and JSON parsed by the `SimpleJwksCache`).
The default implementation, the `SimpleFetcher`, has basic machinery to do fetches over HTTPS. It does 1 (immediate) retry in case of connection errors.

By supplying a custom fetcher when instantiating `SimpleJwksCache`, instead of `SimpleFetcher`, you can implement any retry and backoff scheme you want, or use another HTTPS library:

```typescript
import { JwtVerifier } from "aws-jwt-verify";
import { SimpleJwksCache } from "aws-jwt-verify/jwk";
import { Fetcher } from "aws-jwt-verify/https";
import axios from "axios";

// Use axios to do the HTTPS fetches
class CustomFetcher implements Fetcher {
  instance = axios.create();
  public async fetch(uri: string) {
    return this.instance
      .get(uri, { responseType: "arraybuffer" })
      .then((response) => response.data);
  }
}

const verifier = JwtVerifier.create(
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

### Using a different `JwksParser` with `SimpleJwksCache`

The default `JwksParser` takes the `ArrayBuffer` that the fetcher (see above) returns, and UTF-8 decodes and JSON parses it, and verifies it is a valid JWKS.
If your JWKS is non-standard, you can override the parser, giving you the option to do any transformations needed to make it a standard JWKS:

```typescript
import { JwtVerifier } from "aws-jwt-verify";
import { SimpleJwksCache, assertIsJwks } from "aws-jwt-verify/jwk";

const verifier = JwtVerifier.create(
  {
    issuer: "http://my-tenant.my-idp.com",
  },
  {
    jwksCache: new SimpleJwksCache({
      jwksParser: (buf) => {
        // This is roughly what the default JwksParser does,
        // override with your own logic as needed:
        const jwks = JSON.parse(new TextDecoder().decode(buf));
        assertIsJwks(jwks);
        return jwks;
      },
    }),
  }
);
```

### Configuring the JWKS response timeout and other HTTP options with `Fetcher`

The following configurations are equivalent, use the latter one to set a custom fetch timeout and other HTTP options.

```typescript
import { CognitoJwtVerifier } from "aws-jwt-verify";

// No jwksCache configured explicitly,
// so the default `SimpleJwksCache` with `SimpleFetcher` will be used,
// with a default response timeout of 3000 ms.:
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
import { Fetcher } from "aws-jwt-verify/https";

const verifier = CognitoJwtVerifier.create(
  {
    userPoolId: "<your user pool id>",
    tokenUse: "access", // or "id",
    clientId: "<your client id>",
  },
  {
    jwksCache: new SimpleJwksCache({
      fetcher: new SimpleFetcher({
        defaultRequestOptions: {
          responseTimeout: 3000,
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
import { JwtVerifier } from "aws-jwt-verify";
import {
  SimpleJwksCache,
  SimplePenaltyBox,
  PenaltyBox,
} from "aws-jwt-verify/jwk";

// In this example we use the SimplePenaltyBox, but override the default wait period
const verifier = JwtVerifier.create(
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
const verifier2 = JwtVerifier.create(
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

An example of a sample HTTP Lambda authorizer is included [here](tests/cognito/lib/lambda-authorizer/index.mjs) as part of the test suite for the solution ([format 2.0](https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-lambda-authorizer.html#http-api-lambda-authorizer.payload-format-response)).

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
