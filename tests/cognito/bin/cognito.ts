#!/usr/bin/env node
import "source-map-support/register";
import * as cdk from "@aws-cdk/core";
import { CognitoStack } from "../lib/cognito-stack";

const app = new cdk.App();
new CognitoStack(app, "AwsJwtCognitoTestStack", {
  synthesizer: new cdk.DefaultStackSynthesizer({
    qualifier: "test",
  }),
});
