import { AwsAlbJwksCache } from "../../src/alb-v2";
import {
  allowAllRealNetworkTraffic,
  disallowAllRealNetworkTraffic,
  mockHttpsUri,
} from "./test-util";
import { readFileSync } from "fs";
import { join } from "path";

describe("alb", () => {
  const kid = "abcdefgh-1234-ijkl-5678-mnopqrstuvwx";
  const jwksUri = "https://public-keys.auth.elb.eu-west-1.amazonaws.com";

  const albResponse = readFileSync(join(__dirname, "alb-jwks-test.pem"));
 
  const decomposedJwt ={
    header: {
      alg: "EC256",
      kid
    },
    payload: {},
  };

  beforeAll(() => {
    disallowAllRealNetworkTraffic();
  });
  afterAll(() => {
    allowAllRealNetworkTraffic();
  });

  test("ALB JWKS cache fetches URI one attempt at a time", async () => {
    /**
     * Test what happens when the the JWKS URI is requested multiple times in parallel
     * (e.g. in parallel promises). When this happens only 1 actual HTTPS request should
     * be made to the JWKS URI.
     */
    
    mockHttpsUri(`${jwksUri}/${kid}`, {
      responsePayload: albResponse,
    });

    const jwksCache = new AwsAlbJwksCache();

    const promise1 = jwksCache.getJwk(jwksUri, decomposedJwt);
    const promise2 = jwksCache.getJwk(jwksUri, decomposedJwt);
    expect.assertions(2);
    expect(promise1).toEqual(promise2);
    await Promise.all([promise1, promise2]);
  });

});
