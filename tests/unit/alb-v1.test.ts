import {
  JwtWithoutValidKidError,
} from "../../src/error";
import { AwsAlbJwksCache } from "../../src/alb-v1";
import {
  allowAllRealNetworkTraffic,
  disallowAllRealNetworkTraffic,
  mockHttpsUri,
} from "./test-util";
import { readFileSync } from "fs";
import { join } from "path";

describe("unit tests https", () => {
  const kid = "abcdefgh-1234-ijkl-5678-mnopqrstuvwx";
  const jwksUri = "https://public-keys.auth.elb.eu-west-1.amazonaws.com";
  const jwksUriWithKid = `https://public-keys.auth.elb.eu-west-1.amazonaws.com/${kid}`;

  const albResponse = readFileSync(join(__dirname, "alb-jwks-test.pem"));
  const jwk = {
    kid: kid,
    use: "sig",
    kty: "EC",
    x: "GBJCbjNusVteS__606LS3fgYrhQyvfAh-GbOfy2n7rU",
    y: "oBuN90bW-AvxscoesVaE7ryPISjqseKgio6H5ZO5xmk",
    crv: "P-256",
  };
  const jwks = {
    keys: [jwk],
  };
  const getDecomposedJwt = (kidParam?: string) => ({
    header: {
      alg: "EC256",
      kid: kidParam ?? kid,
    },
    payload: {},
  });

  beforeAll(() => {
    disallowAllRealNetworkTraffic();
  });
  afterAll(() => {
    allowAllRealNetworkTraffic();
  });

  test("ALB JWKS cache error flow: kid empty", () => {
    const jwksCache = new AwsAlbJwksCache();
    expect.assertions(1);
    return expect(
      jwksCache.getJwk(jwksUri, { header: { alg: "EC256" }, payload: {} })
    ).rejects.toThrow(JwtWithoutValidKidError);
  });

  test("ALB JWKS add cache return not implemented exception", () => {
    const jwksCache = new AwsAlbJwksCache();
    return expect(jwksCache.addJwks).toThrow("Method not implemented.");
  });

  test("ALB JWKS get JWKS return not implemented exception", () => {
    const jwksCache = new AwsAlbJwksCache();
    expect.assertions(1);
    return expect(jwksCache.getJwks()).rejects.toThrow(
      "Method not implemented."
    );
  });

  test("ALB JWKS cache fetches URI one attempt at a time", async () => {
    /**
     * Test what happens when the the JWKS URI is requested multiple times in parallel
     * (e.g. in parallel promises). When this happens only 1 actual HTTPS request should
     * be made to the JWKS URI.
     */
    
    mockHttpsUri(jwksUriWithKid, {
      responsePayload: albResponse,
    });

    const jwksCache = new AwsAlbJwksCache();

    const fetch = jest.spyOn(jwksCache.simpleJwksCache.fetcher,"fetch");

    const promise1 = jwksCache.getJwk(jwksUri, getDecomposedJwt());
    const promise2 = jwksCache.getJwk(jwksUri, getDecomposedJwt());
    expect.assertions(2);
    expect(promise1).toEqual(promise2);
    await Promise.all([promise1, promise2]);
    expect(fetch).toHaveBeenCalledTimes(1);
  });

});
