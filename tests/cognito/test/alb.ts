// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import * as outputs from "../outputs.json";
import { JSDOM, CookieJar } from "jsdom";
import * as assert from "node:assert";

const {
  AwsJwtCognitoTestStack: {
    UserPoolUser: username,
    UserPoolUserPassword: password,
    ApplicationLoadBalancerUrl: albUrl,
  },
} = outputs;

/**
 * Issue a GET request against the test AWS ALB, which will prompt the "user" to sign in with the Amazon Cognito Hosted UI.
 * This sign-in is executed automatically, by web scraping the Amazon Cognito Hosted UI (using `jsdom` library).
 *
 * @returns the tokens from the AWS ALB response (our test AWS Lambda function is coded to return these)
 */
export async function callAlbAndSignInWithHostedUi() {
  const fetcher = new CookieAwareFetcher();

  /**
   * Initial GET request to ALB, should lead to redirect to Hosted UI
   */
  const albResponse1 = await fetcher.fetch(albUrl);
  assert.equal(albResponse1.status, 302);
  const cognitoHostedUiLocation1 = albResponse1.headers.get("location")!;
  assert.notEqual(cognitoHostedUiLocation1, null);

  /**
   * Initial GET request to Cognito Hosted UI, should lead to redirect to /login path
   */
  const cognitoResponse1 = await fetcher.fetch(cognitoHostedUiLocation1);
  assert.equal(cognitoResponse1.status, 302);
  const cognitoHostedUiLocation2 = cognitoResponse1.headers.get("location")!;
  assert.notEqual(cognitoHostedUiLocation1, null);

  /**
   * GET request to Cognito Hosted UI /login path
   */
  const cognitoResponse2 = await fetcher.fetch(cognitoHostedUiLocation2);
  assert.equal(cognitoResponse2.status, 200);

  const body = await cognitoResponse2.text();
  const html = new JSDOM(body);
  const form = html.window.document.querySelector("form") as HTMLFormElement;
  assert.notEqual(form, null);

  const csrfToken = form.querySelector(
    'input[name="_csrf"]'
  ) as HTMLInputElement;
  assert.notEqual(csrfToken, null);

  const cognitoHostedUiLocation3 = new URL(
    form.action,
    cognitoHostedUiLocation2
  ).href;

  /**
   * Simulate the submission of the form (POST) with username and password.
   * This should lead to a redirect to the ALB's idpresponse path (if username and password are ok)
   */
  const cognitoResponse3 = await fetcher.fetch(cognitoHostedUiLocation3, {
    method: form.method,
    headers: {
      "content-type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams({
      _csrf: csrfToken.value,
      username,
      password,
    }).toString(),
  });

  assert.equal(cognitoResponse3.status, 302);
  const albLocation2 = cognitoResponse3.headers.get("location")!;
  assert.notEqual(albLocation2, null);

  /**
   * GET request to ALB idpresponse path, should lead to redirect to the original ALB path
   */
  const albResponse2 = await fetcher.fetch(albLocation2);

  assert.equal(albResponse2.status, 302);
  const albLocation3 = albResponse2.headers.get("location")!;
  assert.notEqual(albLocation3, null);

  /**
   * GET request to ALB path, we are now signed in, and should get our payload back!
   */
  const albResponse3 = await fetcher.fetch(albLocation3);

  assert.equal(albResponse3.status, 200);
  const albEventPayload = await albResponse3.json();

  const {
    "x-amzn-oidc-accesstoken": cognitoAccessToken,
    "x-amzn-oidc-data": albToken,
  } = albEventPayload.headers;

  return {
    cognitoAccessToken,
    albToken,
  };
}

class CookieAwareFetcher {
  constructor(private cookieJar = new CookieJar()) {}

  async fetch(
    url: string,
    init?: Parameters<typeof fetch>[1]
  ): ReturnType<typeof fetch> {
    return fetch(url, {
      redirect: "manual",
      ...init,
      headers: {
        ...init?.headers,
        cookie: this.cookieJar.getCookieStringSync(url),
      },
    }).then((response) => {
      response.headers.getSetCookie().forEach((cookie) => {
        this.cookieJar.setCookieSync(cookie, url);
      });
      return response;
    });
  }
}
