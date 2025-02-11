#!/usr/bin/env node
import "source-map-support/register";
import * as cdk from "aws-cdk-lib";
import { AwsSolutionsChecks } from "cdk-nag";
import { Aspects } from "aws-cdk-lib";
import { CognitoStack } from "../lib/cognito-stack";
import "dotenv/config";

const { HOSTED_ZONE_ID, HOSTED_ZONE_NAME, ALB_DOMAIN_NAME } = process.env;

if (!HOSTED_ZONE_ID || !HOSTED_ZONE_NAME || !ALB_DOMAIN_NAME) {
  throw new Error(
    "Please create an .env file with values for HOSTED_ZONE_ID, HOSTED_ZONE_NAME and ALB_DOMAIN_NAME"
  );
}

const app = new cdk.App();
Aspects.of(app).add(new AwsSolutionsChecks({ verbose: true }));
new CognitoStack(app, "AwsJwtCognitoTestStack", {
  albDomainName: ALB_DOMAIN_NAME,
  hostedZoneId: HOSTED_ZONE_ID,
  hostedZoneName: HOSTED_ZONE_NAME,
});
