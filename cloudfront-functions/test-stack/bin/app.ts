#!/usr/bin/env node
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import * as cdk from "aws-cdk-lib";
import { CloudFrontFunctionsTestStack } from "../lib/stack";

const app = new cdk.App();
// Optional tags for every resource, from the "tags" context (cdk.json, ~/.cdk.json or -c)
const tags = app.node.tryGetContext("tags") as
  Record<string, string> | undefined;
Object.entries(tags ?? {}).forEach(([key, value]) =>
  cdk.Tags.of(app).add(key, String(value))
);
new CloudFrontFunctionsTestStack(app, "aws-jwt-verify-cloudfront-functions", {
  env: { account: process.env.CDK_DEFAULT_ACCOUNT, region: "us-east-1" },
});
