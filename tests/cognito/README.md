# Tests with Cognito JWTs

This is a CDK project that deploys a Cognito User Pool to get JWTs from for testing.
This CDK project's automated tests check that the User Pool's JWTs can indeed be successfully verified by aws-jwt-verify

## How to run the tests

First: Ensure you have run the [installation instructions](../../README.md) for aws-jwt-verify, so that you have a testable distribution. Then:

- The stack uses a custom CDK bootstrap toolkit. Therefore, it's necessary to first deploy the bootstrap toolkit stack
- `aws cloudformation create-stack --template-body file://bootstrap-template.yml --stack-name AwsJwtVerifyTest-toolkit --capabilities CAPABILITY_NAMED_IAM`: deploy the bootstrap toolkit stack to your default AWS account/region
- `cdk deploy -O outputs.json --toolkit-stack-name AwsJwtVerifyTest-toolkit`: deploy the stack to your default AWS account/region, saving outputs to `outputs.json`
- `npm run test`: execute the automated tests, this uses the outputs from `outputs.json`
