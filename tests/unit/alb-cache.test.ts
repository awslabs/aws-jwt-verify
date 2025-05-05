import { AlbJwksCache } from "../../src/alb-cache";
import {
  AlbJwksNotExposedError,
  JwksNotAvailableInCacheError,
  JwksValidationError,
  JwkValidationError,
  JwtWithoutValidKidError,
} from "../../src/error";
import {
  allowAllRealNetworkTraffic,
  disallowAllRealNetworkTraffic,
  generateKeyPair,
} from "./test-util";

describe("unit tests AlbJwksCache", () => {
  const jwksUri = "https://public-keys.auth.elb.eu-west-1.amazonaws.com";
  let keypair: ReturnType<typeof generateKeyPair>;
  const getDecomposedJwt = (kid?: string) => ({
    header: {
      alg: "EC256",
      kid: kid ?? keypair.jwk.kid ?? "kid",
    },
    payload: {},
  });
  const getAlbResponseArrayBuffer = () => {
    const encoder = new TextEncoder();
    return encoder.encode(keypair.publicKeyPem).buffer;
  };
  beforeAll(() => {
    keypair = generateKeyPair({
      kid: "00000000-0000-0000-0000-000000000000",
      kty: "EC",
      alg: "ES256",
    });
    disallowAllRealNetworkTraffic();
  });
  afterAll(() => {
    allowAllRealNetworkTraffic();
  });

  test("ALB JWKS cache happy flow", () => {
    const fetcher = {
      fetch: jest.fn(async () => getAlbResponseArrayBuffer()),
    };
    const jwksCache = new AlbJwksCache({ fetcher });
    expect.assertions(1);
    return expect(
      jwksCache.getJwk(jwksUri, getDecomposedJwt())
    ).resolves.toEqual(keypair.jwk);
  });

  test("ALB JWKS cache error flow: kid empty", () => {
    const jwksCache = new AlbJwksCache();
    expect.assertions(1);
    return expect(
      jwksCache.getJwk(jwksUri, { header: { alg: "EC256" }, payload: {} })
    ).rejects.toThrow(JwtWithoutValidKidError);
  });

  test("ALB JWKS cache error flow: fetcher error", () => {
    const errorExpected = new Error("fetcher error");
    const jwksCache = new AlbJwksCache({
      fetcher: {
        fetch: async () => {
          throw errorExpected;
        },
      },
    });
    expect.assertions(1);
    return expect(
      jwksCache.getJwk(jwksUri, getDecomposedJwt())
    ).rejects.toThrow(errorExpected);
  });

  test("ALB JWKS cache returns cached JWK", () => {
    const jwksCache = new AlbJwksCache();
    jwksCache.addJwks(jwksUri, keypair.jwks);
    expect(jwksCache.getCachedJwk(jwksUri, getDecomposedJwt())).toEqual(
      keypair.jwk
    );
  });

  test("ALB JWKS cache returns no JWK", () => {
    const jwksCache = new AlbJwksCache();
    expect(() => jwksCache.getCachedJwk(jwksUri, getDecomposedJwt())).toThrow(
      JwksNotAvailableInCacheError
    );
  });

  test("ALB JWKS add cache return multiple JWK exception", () => {
    const jwksCache = new AlbJwksCache();
    expect(() =>
      jwksCache.addJwks(jwksUri, {
        keys: [keypair.jwk, keypair.jwk],
      })
    ).toThrow(JwksValidationError);
  });

  test("ALB JWKS add cache return no kid", () => {
    const jwksCache = new AlbJwksCache();
    expect(() =>
      jwksCache.addJwks(jwksUri, {
        keys: [
          {
            kty: "EC",
            alg: "ES256",
          },
        ],
      })
    ).toThrow(JwkValidationError);
  });

  test("ALB JWKS get JWKS return not implemented exception", () => {
    const jwksCache = new AlbJwksCache();
    expect.assertions(1);
    return expect(jwksCache.getJwks()).rejects.toThrow(
      new AlbJwksNotExposedError("AWS ALB does not expose JWKS")
    );
  });

  test("ALB JWKS cache fetches URI one attempt at a time", async () => {
    /**
     * Test what happens when the the JWKS URI is requested multiple times in parallel
     * (e.g. in parallel promises). When this happens only 1 actual HTTPS request should
     * be made to the JWKS URI.
     */
    const fetcher = {
      fetch: jest.fn(async () => getAlbResponseArrayBuffer()),
    };
    const jwksCache = new AlbJwksCache({
      fetcher,
    });
    const promise1 = jwksCache.getJwk(jwksUri, getDecomposedJwt());
    const promise2 = jwksCache.getJwk(jwksUri, getDecomposedJwt());
    expect.assertions(2);
    expect(promise1).toEqual(promise2);
    await Promise.all([promise1, promise2]);
    expect(fetcher.fetch).toHaveBeenCalledTimes(1);
  });
});
