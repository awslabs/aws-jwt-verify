# Tests with the CloudFront Functions JWT verifier

This CDK project deploys the [CloudFront Functions JWT verifier](../jwt-verifier.js) in front of a protected origin, with a Cognito User Pool to get JWTs from. [e2e.sh](e2e.sh) then calls the distribution with valid and invalid JWTs.

The stack (`aws-jwt-verify-cloudfront-functions`, in `us-east-1`) contains:

- A Cognito User Pool with two app clients and a test user. The user's password is generated in Secrets Manager at deploy time and is never printed.
- A CloudFront KeyValueStore, the JWKS cache.
- A distribution. Its default behavior runs the verifier in front of a Lambda function URL behind origin access control, which echoes the `x-jwt-*` headers it gets. The Cognito issuer is an origin with no cache behavior, so only the verifier's network call reaches it.
- `/unreachable/*` and `/slow/*`: the same verifier, pointed at an issuer that does not resolve and at one that does not answer.

Every resource gets the tags in the optional `tags` context, e.g. `cdk deploy -c tags='{"team":"x"}'`, or set them in `~/.cdk.json`.

## How to run the tests

- Install dependencies: `npm install`
- Bootstrap your AWS account for AWS CDK: `npx cdk bootstrap`
- Deploy, saving outputs to `outputs.json`: `npm run deploy`
- Run the end-to-end test: `npm run e2e`

The end-to-end test signs in with `AdminInitiateAuth` and checks these cases:

- A valid access token, with the JWK in the KeyValueStore (no network call), and with the kid missing from it (the JWKS is fetched).
- An ES256 token, and the `x-jwt-sub` header a viewer sends is dropped.
- A `401` for these: no token, a malformed token, an expired token, the wrong client id, the wrong `token_use`, a forged signature, and an unknown kid.
- A `503` when the issuer is unreachable or slow.

The ES256, expired and unknown kid tokens are signed with keys made for the run ([e2e-tokens.ts](e2e-tokens.ts)). Their public keys are in the KeyValueStore only while the test runs. At the end, the KeyValueStore holds the Cognito JWKS.
