import * as apigw from "@aws-cdk/aws-apigatewayv2";
import * as apigwauth from "@aws-cdk/aws-apigatewayv2-authorizers";
import * as apigwint from "@aws-cdk/aws-apigatewayv2-integrations";
import * as cognito from "@aws-cdk/aws-cognito";
import * as lambda from "@aws-cdk/aws-lambda";
import * as cdk from "@aws-cdk/core";
import * as cr from "@aws-cdk/custom-resources";
import * as path from "path";

export class CognitoStack extends cdk.Stack {
  constructor(scope: cdk.Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);
    new cdk.CfnOutput(this, "UserPoolRegion", {
      value: this.region,
    });

    const cup = new cognito.UserPool(this, "AwsJwtTestUserPool", {
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      signInAliases: {
        email: true,
      },
    });
    new cdk.CfnOutput(this, "UserPoolId", {
      value: cup.userPoolId,
    });

    const oauthDomain = cup.addDomain("OAuthDomain", {
      cognitoDomain: {
        domainPrefix: `oauthdomain-${this.account}`,
      },
    });
    new cdk.CfnOutput(this, "HostedUIUrl", {
      value: oauthDomain.baseUrl(),
    });

    const user = new cognito.CfnUserPoolUser(this, "TestUser", {
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

    const password = "Testing1234@";
    const setPasswordApiCall: cr.AwsSdkCall = {
      service: "CognitoIdentityServiceProvider",
      action: "adminSetUserPassword",
      parameters: {
        UserPoolId: cup.userPoolId,
        Username: user.username!,
        Password: password,
        Permanent: true,
      },
      physicalResourceId: cr.PhysicalResourceId.of(user.username!),
    };
    new cr.AwsCustomResource(this, "PasswordSetter", {
      resourceType: "Custom::PasswordSetter",
      onCreate: setPasswordApiCall,
      onUpdate: setPasswordApiCall,
      policy: cr.AwsCustomResourcePolicy.fromSdkCalls({
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

    const clientSecretApiCall: cr.AwsSdkCall = {
      service: "CognitoIdentityServiceProvider",
      action: "describeUserPoolClient",
      parameters: {
        UserPoolId: cup.userPoolId,
        ClientId: clientWithSecret.userPoolClientId,
      },
      physicalResourceId: cr.PhysicalResourceId.of(
        clientWithSecret.userPoolClientId
      ),
      outputPath: "UserPoolClient.ClientSecret",
    };
    const clientSecretGetter = new cr.AwsCustomResource(
      this,
      "ClientSecretGetter",
      {
        resourceType: "Custom::ClientSecretGetter",
        onCreate: clientSecretApiCall,
        onUpdate: clientSecretApiCall,
        policy: cr.AwsCustomResourcePolicy.fromSdkCalls({
          resources: [cup.userPoolArn],
        }),
      }
    );
    new cdk.CfnOutput(this, "UserPoolClientWithSecretValue", {
      value: clientSecretGetter.getResponseField("UserPoolClient.ClientSecret"),
    });

    // Deploy HTTP API with custom authorizer:
    const mock = new lambda.Function(this, "MockEndpoint", {
      runtime: lambda.Runtime.NODEJS_14_X,
      code: lambda.Code.fromInline(`exports.handler = async () => ({
        statusCode: 200,
        headers: { "Content-Type": "application/json" },
        body: "{\\"private\\":\\"content!\\"}"
      })`),
      handler: "index.handler",
    });
    const lambdaAuthorizer = new lambda.Function(
      this,
      "LambdaAuthorizerHandler",
      {
        runtime: lambda.Runtime.NODEJS_14_X,
        code: lambda.Code.fromAsset(path.join(__dirname, "lambda-authorizer")),
        handler: "index.handler",
        environment: {
          USER_POOL_ID: cup.userPoolId,
          CLIENT_ID: client.userPoolClientId,
          USER_EMAIL: user.username!,
        },
      }
    );
    const apiAuthorizer = new apigwauth.HttpLambdaAuthorizer({
      authorizerName: "LambdaAuthorizer",
      responseTypes: [apigwauth.HttpLambdaResponseType.SIMPLE],
      handler: lambdaAuthorizer,
    });
    const httpApi = new apigw.HttpApi(this, "HttpApi");
    httpApi.addRoutes({
      path: "/mock",
      methods: [apigw.HttpMethod.GET],
      integration: new apigwint.LambdaProxyIntegration({
        handler: mock,
      }),
      authorizer: apiAuthorizer,
    });

    new cdk.CfnOutput(this, "HttpApiEndpoint", {
      value: `${httpApi.url}mock`,
    });
  }
}
