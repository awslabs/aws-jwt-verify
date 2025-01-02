# Tests with Cognito JWTs

This is a CDK project that deploys a Cognito User Pool to get JWTs from for testing.
This CDK project's automated tests check that the User Pool's JWTs can indeed be successfully verified by aws-jwt-verify

## Prereqs

You need to have an existing Route 53 public hosted zone in your account (because we will setup AWS ALB with an HTTPS certificate).

## How to run the tests

- Clone the repo: `git clone https://github.com/awslabs/aws-jwt-verify`
- Install dev dependencies and create installable dist: `cd aws-jwt-verify && npm install && npm run pack-for-tests`
- Install CDK dependencies: `cd tests/cognito && npm install`
- Copy `.env.TEMPLATE` to `.env` and populate with the right values:
  - HOSTED_ZONE_ID: the ID of an existing Route 53 public hosted zone in your account
  - HOSTED_ZONE_NAME: the domain name of the hosted zone
  - ALB_DOMAIN_NAME: the domain name that you want to give to the ALB (likely a subdomain of the hosted zone)
- Bootstrap your AWS account for AWS CDK: `cdk bootstrap`
- Deploy the stack to your default AWS account/region, saving outputs to `outputs.json`: `cdk deploy -O outputs.json`
- Execute the automated tests, this uses the outputs from `outputs.json`: `npm run test`

Next time, you can just run `npm run test` from the current working directory, or `npm run test:cognito` from the workspace root.
