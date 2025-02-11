// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import * as cdk from "aws-cdk-lib";
import { NagSuppressions } from "cdk-nag";
import { Construct } from "constructs";
import * as path from "node:path";

export class CognitoStack extends cdk.Stack {
  constructor(
    scope: Construct,
    id: string,
    props: {
      hostedZoneId: string;
      hostedZoneName: string;
      albDomainName: string;
    } & cdk.StackProps
  ) {
    super(scope, id, props);

    NagSuppressions.addStackSuppressions(this, [
      {
        id: "AwsSolutions-L1",
        reason: "Avoid workshop error when NODEJS runtime updates",
      },
      {
        id: "AwsSolutions-IAM4",
        reason: "Needs access to write to CloudWatch Logs",
        appliesTo: [
          "Policy::arn:<AWS::Partition>:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
        ],
      },
      {
        id: "AwsSolutions-ELB2",
        reason: "Testing does not need access logging enabled",
      },
      {
        id: "AwsSolutions-APIG1",
        reason: "Testing does not need access logging enabled",
      },
      {
        id: "AwsSolutions-VPC7",
        reason: "Testing does not need flow logging enabled",
      },
    ]);

    new cdk.CfnOutput(this, "UserPoolRegion", {
      value: this.region,
    });

    const cup = new cdk.aws_cognito.UserPool(this, "AwsJwtTestUserPool", {
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      signInAliases: {
        email: true,
      },
      passwordPolicy: {
        minLength: 20,
        requireDigits: false,
        requireLowercase: false,
        requireSymbols: false,
        requireUppercase: false,
      },
    });
    new cdk.CfnOutput(this, "UserPoolId", {
      value: cup.userPoolId,
    });

    NagSuppressions.addResourceSuppressions(cup, [
      {
        id: "AwsSolutions-COG1",
        reason: "Testing does not need password policy.",
      },
      {
        id: "AwsSolutions-COG2",
        reason: "Testing does not use MFA.",
      },
      {
        id: "AwsSolutions-COG3",
        reason: "Testing does not use advanced security features.",
      },
    ]);

    const oauthDomain = cup.addDomain("OAuthDomain", {
      cognitoDomain: {
        domainPrefix: `oauthdomain-${this.account}`,
      },
    });
    new cdk.CfnOutput(this, "HostedUIUrl", {
      value: oauthDomain.baseUrl(),
    });

    const user = new cdk.aws_cognito.CfnUserPoolUser(this, "TestUser", {
      userPoolId: cup.userPoolId,
      messageAction: "SUPPRESS",
      desiredDeliveryMediums: ["EMAIL"],
      userAttributes: [
        {
          name: "email",
          value: "johndoe@example.com",
        },
        {
          name: "email_verified",
          value: "true",
        },
        {
          name: "name",
          value: "John Doe +/=-_",
        },
      ],
      username: "johndoe@example.com",
    });
    new cdk.CfnOutput(this, "UserPoolUser", {
      value: user.username!,
    });

    const password = cdk.Fn.select(2, cdk.Fn.split("/", cdk.Aws.STACK_ID));
    const setPasswordApiCall: cdk.custom_resources.AwsSdkCall = {
      service: "CognitoIdentityServiceProvider",
      action: "adminSetUserPassword",
      parameters: {
        UserPoolId: cup.userPoolId,
        Username: user.username!,
        Password: password,
        Permanent: true,
      },
      physicalResourceId: cdk.custom_resources.PhysicalResourceId.of(
        user.username!
      ),
    };
    new cdk.custom_resources.AwsCustomResource(this, "PasswordSetter", {
      resourceType: "Custom::PasswordSetter",
      onCreate: setPasswordApiCall,
      onUpdate: setPasswordApiCall,
      policy: cdk.custom_resources.AwsCustomResourcePolicy.fromSdkCalls({
        resources: [cup.userPoolArn],
      }),
    });
    new cdk.CfnOutput(this, "UserPoolUserPassword", {
      value: password,
    });

    const resourceServer = cup.addResourceServer("MyAPI", {
      identifier: "my-api",
      scopes: [
        {
          scopeName: "read",
          scopeDescription: "Read access",
        },
      ],
      userPoolResourceServerName: "My Authenticated API",
    });
    new cdk.CfnOutput(this, "ResourceServerWithScope", {
      value: `${resourceServer.userPoolResourceServerId}/read`,
    });

    const client = cup.addClient("UserPoolClient", {
      authFlows: {
        userPassword: true,
        adminUserPassword: true,
        userSrp: true,
      },
    });
    new cdk.CfnOutput(this, "UserPoolClientId", {
      value: client.userPoolClientId,
    });

    const clientWithSecret = cup.addClient("UserPoolClientWithSecret", {
      generateSecret: true,
      oAuth: {
        scopes: [
          {
            scopeName: `${resourceServer.userPoolResourceServerId}/read`,
          },
        ],
        flows: {
          clientCredentials: true,
        },
      },
    });
    new cdk.CfnOutput(this, "UserPoolClientWithSecretClientId", {
      value: clientWithSecret.userPoolClientId,
    });

    const clientSecretApiCall: cdk.custom_resources.AwsSdkCall = {
      service: "CognitoIdentityServiceProvider",
      action: "describeUserPoolClient",
      parameters: {
        UserPoolId: cup.userPoolId,
        ClientId: clientWithSecret.userPoolClientId,
      },
      physicalResourceId: cdk.custom_resources.PhysicalResourceId.of(
        clientWithSecret.userPoolClientId
      ),
      outputPaths: ["UserPoolClient.ClientSecret"],
    };
    const clientSecretGetter = new cdk.custom_resources.AwsCustomResource(
      this,
      "ClientSecretGetter",
      {
        resourceType: "Custom::ClientSecretGetter",
        onCreate: clientSecretApiCall,
        onUpdate: clientSecretApiCall,
        policy: cdk.custom_resources.AwsCustomResourcePolicy.fromSdkCalls({
          resources: [cup.userPoolArn],
        }),
      }
    );
    new cdk.CfnOutput(this, "UserPoolClientWithSecretValue", {
      value: clientSecretGetter.getResponseField("UserPoolClient.ClientSecret"),
    });

    // Deploy HTTP API with custom authorizer:
    const mock = new cdk.aws_lambda.Function(this, "MockEndpoint", {
      runtime: cdk.aws_lambda.Runtime.NODEJS_LATEST,
      code: cdk.aws_lambda.Code.fromInline(`exports.handler = async () => ({
        statusCode: 200,
        headers: { "Content-Type": "application/json" },
        body: "{\\"private\\":\\"content!\\"}"
      })`),
      handler: "index.handler",
    });
    const lambdaAuthorizer = new cdk.aws_lambda.Function(
      this,
      "LambdaAuthorizerHandler",
      {
        runtime: cdk.aws_lambda.Runtime.NODEJS_LATEST,
        code: cdk.aws_lambda.Code.fromAsset(
          path.join(__dirname, "lambda-authorizer")
        ),
        handler: "index.handler",
        environment: {
          USER_POOL_ID: cup.userPoolId,
          CLIENT_ID: client.userPoolClientId,
          USER_EMAIL: user.username!,
        },
      }
    );
    const apiAuthorizer =
      new cdk.aws_apigatewayv2_authorizers.HttpLambdaAuthorizer(
        "LambdaAuthorizer",
        lambdaAuthorizer,
        {
          authorizerName: "LambdaAuthorizer",
          responseTypes: [
            cdk.aws_apigatewayv2_authorizers.HttpLambdaResponseType.SIMPLE,
          ],
        }
      );
    const httpApi = new cdk.aws_apigatewayv2.HttpApi(this, "HttpApi");
    httpApi.addRoutes({
      path: "/mock",
      methods: [cdk.aws_apigatewayv2.HttpMethod.GET],
      integration: new cdk.aws_apigatewayv2_integrations.HttpLambdaIntegration(
        "MockIntegration",
        mock
      ),
      authorizer: apiAuthorizer,
    });

    new cdk.CfnOutput(this, "HttpApiEndpoint", {
      value: `${httpApi.url}mock`,
    });

    /**
     * AWS ALB
     */

    const vpc = new cdk.aws_ec2.Vpc(this, "VPC", {
      maxAzs: 2,
      natGateways: 0,
      subnetConfiguration: [
        {
          cidrMask: 24,
          name: "public",
          subnetType: cdk.aws_ec2.SubnetType.PUBLIC,
        },
      ],
    });

    const alb = new cdk.aws_elasticloadbalancingv2.ApplicationLoadBalancer(
      this,
      "ALB",
      {
        vpc,
        internetFacing: true,
      }
    );
    new cdk.CfnOutput(this, "ApplicationLoadBalancerArn", {
      value: alb.loadBalancerArn,
    });

    const scopes = [cdk.aws_cognito.OAuthScope.OPENID];
    const albClient = cup.addClient("AlbClient", {
      generateSecret: true,
      oAuth: {
        flows: {
          authorizationCodeGrant: true,
        },
        scopes,
        callbackUrls: [`https://${props.albDomainName}/oauth2/idpresponse`],
      },
    });
    new cdk.CfnOutput(this, "UserPoolClientIdAlb", {
      value: albClient.userPoolClientId,
    });

    const hostedZoneRef = cdk.aws_route53.HostedZone.fromHostedZoneAttributes(
      this,
      "HostedZone",
      {
        hostedZoneId: props.hostedZoneId,
        zoneName: props.hostedZoneName,
      }
    );

    const cert = new cdk.aws_certificatemanager.Certificate(
      this,
      "Certificate",
      {
        domainName: props.albDomainName,
        validation:
          cdk.aws_certificatemanager.CertificateValidation.fromDns(
            hostedZoneRef
          ),
      }
    );

    const albMock = new cdk.aws_lambda.Function(this, "MockEndpointAlb", {
      runtime: cdk.aws_lambda.Runtime.NODEJS_LATEST,
      code: cdk.aws_lambda.Code
        .fromInline(`exports.handler = async (event) => ({
        statusCode: 200,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(event)
      })`),
      handler: "index.handler",
    });

    alb.addListener("Listener", {
      open: true,
      certificates: [cert],
      protocol: cdk.aws_elasticloadbalancingv2.ApplicationProtocol.HTTPS,
      sslPolicy: cdk.aws_elasticloadbalancingv2.SslPolicy.RECOMMENDED_TLS, // This enforces TLS 1.2 and higher
      defaultAction:
        new cdk.aws_elasticloadbalancingv2_actions.AuthenticateCognitoAction({
          userPool: cup,
          userPoolClient: albClient,
          userPoolDomain: oauthDomain,
          scope: scopes.map((s) => s.scopeName).join(" "),
          next: cdk.aws_elasticloadbalancingv2.ListenerAction.forward([
            new cdk.aws_elasticloadbalancingv2.ApplicationTargetGroup(
              this,
              "LambdaTarget",
              {
                targets: [
                  new cdk.aws_elasticloadbalancingv2_targets.LambdaTarget(
                    albMock
                  ),
                ],
              }
            ),
          ]),
        }),
    });
    NagSuppressions.addResourceSuppressions(
      alb,
      [
        {
          id: "AwsSolutions-EC23",
          reason: "Testing needs an open Security Group",
        },
      ],
      true
    );

    new cdk.aws_route53.ARecord(this, "AliasRecord", {
      zone: hostedZoneRef,
      target: cdk.aws_route53.RecordTarget.fromAlias(
        new cdk.aws_route53_targets.LoadBalancerTarget(alb)
      ),
      recordName: props.albDomainName,
    });

    new cdk.CfnOutput(this, "ApplicationLoadBalancerUrl", {
      value: `https://${props.albDomainName}`,
    });
  }
}
