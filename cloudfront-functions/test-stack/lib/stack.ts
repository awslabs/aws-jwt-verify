// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import * as cdk from "aws-cdk-lib";
import * as cloudfront from "aws-cdk-lib/aws-cloudfront";
import * as origins from "aws-cdk-lib/aws-cloudfront-origins";
import * as cognito from "aws-cdk-lib/aws-cognito";
import * as iam from "aws-cdk-lib/aws-iam";
import * as lambda from "aws-cdk-lib/aws-lambda";
import * as secretsmanager from "aws-cdk-lib/aws-secretsmanager";
import * as cr from "aws-cdk-lib/custom-resources";
import { Construct } from "constructs";
import {
  CloudFrontFunctionOptions,
  cognitoIssuer,
  generateCloudFrontFunction,
} from "../../generate";

const TEST_USER = "test-user";

/**
 * Test stack for the CloudFront Functions JWT verifier:
 * - a Cognito user pool, two app clients and a test user (password generated at deploy time)
 * - a KeyValueStore, the JWKS cache
 * - a distribution whose default behavior runs the verifier in front of an echo origin
 *   (Lambda function URL behind OAC), plus the Cognito issuer as an origin with no behavior
 * - /unreachable/* and /slow/*: the same verifier, pointed at an issuer origin that does not
 *   resolve and at one that does not answer, to test that it fails closed
 */
export class CloudFrontFunctionsTestStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    // --- Cognito -------------------------------------------------------------------
    const userPool = new cognito.UserPool(this, "UserPool", {
      selfSignUpEnabled: false,
      signInAliases: { username: true },
      accountRecovery: cognito.AccountRecovery.NONE,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });
    const clientProps = {
      generateSecret: false,
      authFlows: { adminUserPassword: true },
    };
    const client = userPool.addClient("Client", clientProps);
    const otherClient = userPool.addClient("OtherClient", clientProps);

    const createUser = new cr.AwsCustomResource(this, "TestUser", {
      onCreate: {
        service: "CognitoIdentityServiceProvider",
        action: "adminCreateUser",
        parameters: {
          UserPoolId: userPool.userPoolId,
          Username: TEST_USER,
          MessageAction: "SUPPRESS",
        },
        physicalResourceId: cr.PhysicalResourceId.of(TEST_USER),
      },
      policy: cr.AwsCustomResourcePolicy.fromSdkCalls({
        resources: [userPool.userPoolArn],
      }),
      installLatestAwsSdk: false,
    });

    // The password is generated in Secrets Manager and set by a Lambda function that reads
    // it, so its value is never in the template or in any output.
    const password = new secretsmanager.Secret(this, "TestUserPassword", {
      generateSecretString: {
        passwordLength: 32,
        requireEachIncludedType: true,
        excludeCharacters: "\"'\\`{}/@ ",
      },
    });
    const setPasswordFn = new lambda.Function(this, "SetPasswordFn", {
      runtime: lambda.Runtime.NODEJS_22_X,
      handler: "index.handler",
      timeout: cdk.Duration.seconds(30),
      code: lambda.Code.fromInline(`
const { SecretsManagerClient, GetSecretValueCommand } = require("@aws-sdk/client-secrets-manager");
const { CognitoIdentityProviderClient, AdminSetUserPasswordCommand } = require("@aws-sdk/client-cognito-identity-provider");
exports.handler = async (event) => {
  const p = event.ResourceProperties;
  if (event.RequestType !== "Delete") {
    const secret = await new SecretsManagerClient({}).send(new GetSecretValueCommand({ SecretId: p.SecretArn }));
    await new CognitoIdentityProviderClient({}).send(new AdminSetUserPasswordCommand({
      UserPoolId: p.UserPoolId, Username: p.Username, Password: secret.SecretString, Permanent: true,
    }));
  }
  return { PhysicalResourceId: p.Username + "/password" };
};`),
    });
    password.grantRead(setPasswordFn);
    setPasswordFn.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ["cognito-idp:AdminSetUserPassword"],
        resources: [userPool.userPoolArn],
      })
    );
    const setPassword = new cdk.CustomResource(this, "SetPassword", {
      serviceToken: new cr.Provider(this, "SetPasswordProvider", {
        onEventHandler: setPasswordFn,
      }).serviceToken,
      properties: {
        UserPoolId: userPool.userPoolId,
        Username: TEST_USER,
        SecretArn: password.secretArn,
      },
    });
    setPassword.node.addDependency(createUser);

    // --- Protected origin: echoes what the verifier passed on ------------------------
    const echoFn = new lambda.Function(this, "EchoFn", {
      runtime: lambda.Runtime.NODEJS_22_X,
      handler: "index.handler",
      code: lambda.Code.fromInline(`
exports.handler = async (event) => {
  const h = event.headers || {};
  return {
    statusCode: 200,
    headers: { "content-type": "application/json", "cache-control": "no-store" },
    body: JSON.stringify({ protected: true, sub: h["x-jwt-sub"], clientId: h["x-jwt-client-id"], jwks: h["x-jwt-jwks"] }),
  };
};`),
    });
    const echoUrl = echoFn.addFunctionUrl({
      authType: lambda.FunctionUrlAuthType.AWS_IAM,
    });
    const echoOrigin = origins.FunctionUrlOrigin.withOriginAccessControl(
      echoUrl,
      { originId: "protected" }
    );

    // --- CloudFront ------------------------------------------------------------------
    const kvs = new cloudfront.KeyValueStore(this, "JwksCache", {
      comment: "JWKS cache of the CloudFront Functions JWT verifier",
    });
    const cognitoDomain = cognitoIssuer("", this.region).originDomainName;
    const verifierOptions: CloudFrontFunctionOptions = {
      userPoolId: userPool.userPoolId,
      region: this.region,
      tokenUse: "access",
      clientId: client.userPoolClientId,
    };
    const verifierFunction = (
      name: string,
      extra: Partial<CloudFrontFunctionOptions>
    ) =>
      new cloudfront.Function(this, name, {
        runtime: cloudfront.FunctionRuntime.JS_2_0,
        keyValueStore: kvs,
        code: cloudfront.FunctionCode.fromInline(
          generateCloudFrontFunction({ ...verifierOptions, ...extra })
        ),
      });

    // Only the x-jwt-* headers the verifier sets reach the origin.
    const originRequestPolicy = new cloudfront.OriginRequestPolicy(
      this,
      "VerifiedClaims",
      {
        headerBehavior: cloudfront.OriginRequestHeaderBehavior.allowList(
          "x-jwt-sub",
          "x-jwt-client-id",
          "x-jwt-jwks"
        ),
      }
    );
    const behavior = (fn: cloudfront.Function): cloudfront.BehaviorOptions => ({
      origin: echoOrigin,
      viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
      cachePolicy: cloudfront.CachePolicy.CACHING_DISABLED,
      originRequestPolicy,
      functionAssociations: [
        {
          eventType: cloudfront.FunctionEventType.VIEWER_REQUEST,
          function: fn,
        },
      ],
    });

    const distribution = new cloudfront.Distribution(this, "Distribution", {
      comment: "aws-jwt-verify CloudFront Functions test",
      priceClass: cloudfront.PriceClass.PRICE_CLASS_100,
      defaultBehavior: behavior(verifierFunction("Verifier", {})),
      additionalBehaviors: {
        "/unreachable/*": behavior(
          verifierFunction("VerifierUnreachableIssuer", {
            jwksOriginId: "jwt-issuer-unreachable",
            kvsKeyPrefix: "unreachable:",
          })
        ),
        "/slow/*": behavior(
          verifierFunction("VerifierSlowIssuer", {
            jwksOriginId: "jwt-issuer-slow",
            kvsKeyPrefix: "slow:",
          })
        ),
      },
    });

    // The issuer origins have no cache behavior: only cf.fetch reaches them.
    addOriginWithoutBehavior(
      distribution,
      new origins.HttpOrigin(cognitoDomain, { originId: "jwt-issuer" })
    );
    addOriginWithoutBehavior(
      distribution,
      // .invalid never resolves (RFC 2606)
      new origins.HttpOrigin("issuer.invalid", {
        originId: "jwt-issuer-unreachable",
      })
    );
    addOriginWithoutBehavior(
      distribution,
      // A port the issuer does not listen on: the call times out
      new origins.HttpOrigin(cognitoDomain, {
        originId: "jwt-issuer-slow",
        httpsPort: 4443,
      })
    );

    const out = (id: string, value: string) =>
      new cdk.CfnOutput(this, id, { value });
    out("Region", this.region);
    out("UserPoolId", userPool.userPoolId);
    out("ClientId", client.userPoolClientId);
    out("OtherClientId", otherClient.userPoolClientId);
    out("TestUserName", TEST_USER);
    out("TestUserPasswordSecretName", password.secretName);
    out("KeyValueStoreArn", kvs.keyValueStoreArn);
    out("DistributionId", distribution.distributionId);
    out("DistributionDomainName", distribution.distributionDomainName);
  }
}

/**
 * The Distribution construct adds origins through behaviors only; this calls its addOrigin,
 * the code path behaviors use, for an origin that only cf.fetch targets.
 */
function addOriginWithoutBehavior(
  distribution: cloudfront.Distribution,
  origin: cloudfront.IOrigin
) {
  const d = distribution as unknown as {
    addOrigin?: (origin: cloudfront.IOrigin) => string;
  };
  if (typeof d.addOrigin !== "function") {
    throw new Error("cloudfront.Distribution no longer has addOrigin()");
  }
  d.addOrigin(origin);
}
