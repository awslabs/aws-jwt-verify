# Tests with Cognito JWTs

This is a CDK project that deploys a Cognito User Pool to get JWTs from for testing.
This CDK project's automated tests check that the User Pool's JWTs can indeed be successfully verified by aws-jwt-verify

## How to run the tests

Download and create dist locally:

- Clone the repo: `git clone https://github.com/awslabs/aws-jwt-verify`
- Install dev dependencies and create installable dist: `cd aws-jwt-verify && npm install && npm run dist`
- Install CDK dependencies: `cd tests/cognito && npm install`
- The stack uses a custom CDK bootstrap toolkit. Therefore, it's necessary to first deploy the bootstrap toolkit stack: `aws cloudformation create-stack --template-body file://bootstrap-template.yml --stack-name AwsJwtVerifyTest-toolkit --capabilities CAPABILITY_NAMED_IAM`
- Deploy the stack to your default AWS account/region, saving outputs to `outputs.json`: `cdk deploy -O outputs.json --toolkit-stack-name AwsJwtVerifyTest-toolkit`
- Execute the automated tests, this uses the outputs from `outputs.json`: `npm run test`

Next time, you can just run `npm run test` from the current working directory, or `npm run test:cognito` from the workspace root.
