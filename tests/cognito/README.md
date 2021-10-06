# Tests with Cognito JWTs

This is a CDK project that deploys a Cognito User Pool to get JWTs from for testing.
This CDK project's automated tests check that the User Pool's JWTs can indeed be successfully verified by aws-jwt-verify

## How to run the tests

1. `cdk bootstrap --toolkit-stack-name AwsJwtVerifyTest-toolkit --template bootstrap-template.yml`: the stack uses a custom CDK bootstrap toolkit. Therefore, it's necessary to first deploy the bootstrap toolkit stack.
1. `cdk deploy -O outputs.json --toolkit-stack-name AwsJwtVerifyTest-toolkit`: deploy the stack to your default AWS account/region, saving outputs to `outputs.json`
1. `npm run test`: execute the automated tests, this uses the outputs from `outputs.json`
