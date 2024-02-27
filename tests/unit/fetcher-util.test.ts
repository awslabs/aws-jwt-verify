import { JwtWithoutValidKidError, KidNotFoundInJwksError, WaitPeriodNotYetEndedJwkError } from "../../src/error";
import { AlbUriError, AwsAlbJwksCache, AwsAlbJwksFetcher } from "../../src/fetcher-util";
import { SimplePenaltyBox } from "../../src/jwk";
import { mockHttpsUri, throwOnUnusedMocks } from "./test-util";
import { readFileSync } from "fs";
import { join } from "path";

describe("unit tests https", () => {
  const jwksUri = "https://public-keys.auth.elb.eu-west-1.amazonaws.com/{kid}";
  const publicKeyAlbResponse = readFileSync(
    join(__dirname, "albresponse-test.pem")
  );
  const jwk = {
    kid: "abcdefgh-1234-ijkl-5678-mnopqrstuvwx",
    use: "sig",
    kty: 'EC',
    x: 'GBJCbjNusVteS__606LS3fgYrhQyvfAh-GbOfy2n7rU',
    y: 'oBuN90bW-AvxscoesVaE7ryPISjqseKgio6H5ZO5xmk',
    crv: 'P-256'
  }
  const jwks = {
    keys: [jwk]
  };
  const getDecomposedJwt = (kid?:string ) => ({
    header: {
      alg: "EC256",
      kid: kid ?? jwk.kid,
    },
    payload: {},
  });

  afterEach(() => {
    throwOnUnusedMocks();
  });

  test("ALB JSON fetcher works", () => {
    mockHttpsUri(jwksUri, { responsePayload: publicKeyAlbResponse });
    expect.assertions(1);
    return expect(new AwsAlbJwksFetcher().fetch(jwksUri)).resolves.toEqual(jwks);
  });

  test("ALB JSON fetcher does not validate alb public key URI", () => {
      const wrongUri = `https://public-keys.auth.elb.eu-west-1.amazon.wrong/${jwk.kid}`
      mockHttpsUri(wrongUri, { responsePayload: publicKeyAlbResponse });
      expect.assertions(1);
      return expect(new AwsAlbJwksFetcher().fetch(wrongUri)).rejects.toThrow(AlbUriError);
  });

  test("ALB JSON fetcher does retry once", () => {
    class TcpError extends Error {}
    expect.assertions(1);
    mockHttpsUri(jwksUri, new TcpError("Some TCP error occured"));
    mockHttpsUri(jwksUri, { responsePayload: publicKeyAlbResponse });
    return expect(new AwsAlbJwksFetcher().fetch(jwksUri)).resolves.toEqual(jwks);
  });

  test("ALB JSON fetcher does retry HTTP 429", () => {
    expect.assertions(1);
    mockHttpsUri(jwksUri, {
      responseStatus: 429,
      responsePayload: "WE'RE BUSY RIGHT NOW",
    });
    mockHttpsUri(jwksUri, { responsePayload: publicKeyAlbResponse });
    return expect(new AwsAlbJwksFetcher().fetch(jwksUri)).resolves.toEqual(jwks);
  });

  test("ALB JSON fetcher does not retry twice", () => {
    class TcpError extends Error {}
    expect.assertions(1);
    mockHttpsUri(jwksUri, new TcpError("1st TCP Error"));
    mockHttpsUri(jwksUri, new TcpError("2nd TCP Error"));
    return expect(new AwsAlbJwksFetcher().fetch(jwksUri)).rejects.toThrow(
      `Failed to fetch ${jwksUri}: 2nd TCP Error`
    );
  });

  test("ALB JSON fetcher does not retry non-retryable errors", () => {
    expect.assertions(1);
    mockHttpsUri(jwksUri, { responseStatus: 500, responsePayload: "Nope!\nError" });
    return expect(new AwsAlbJwksFetcher().fetch(jwksUri)).rejects.toThrow(
      `Failed to fetch ${jwksUri}: Status code is 500, expected 200`
    );
  });

  test("ALB JSON fetcher uses defaults provided to the constructor", () => {
    mockHttpsUri(jwksUri, { responsePayload: publicKeyAlbResponse });
    expect.assertions(1);
    return expect(
      new AwsAlbJwksFetcher({
        defaultRequestOptions: { timeout: 100, responseTimeout: 150 },
      }).fetch(jwksUri)
    ).resolves.toEqual(jwks);
  });


  test("ALB JWKS cache returns JWK", () => {
    const jwksCache = new AwsAlbJwksCache({
      fetcher: { fetch: async () => jwks },
    });
    expect.assertions(1);
    return expect(
      jwksCache.getJwk(jwksUri, getDecomposedJwt())
    ).resolves.toEqual(jwk);
  });

  test("ALB JWKS with no kid variable in URI", () => {
    const jwksCache = new AwsAlbJwksCache({
      fetcher: { fetch: async () => jwks },
    });
    expect.assertions(1);
    return expect(
      jwksCache.getJwk("https://public-keys.auth.elb.eu-west-1.amazonaws.com/", getDecomposedJwt())
    ).rejects.toThrow(KidNotFoundInJwksError);
  });

  test("ALB JWKS cache returns cached JWK", () => {
    const jwksCache = new AwsAlbJwksCache({
      fetcher: { fetch: async () => jwks },
    });
    expect(
       jwksCache.getJwk(jwksUri, getDecomposedJwt())
       .then(()=>jwksCache.getCachedJwk(jwksUri, getDecomposedJwt()))
    ).resolves.toEqual(jwk);
  });

  test("ALB JWKS cache error flow: kid empty", () => {
    const jwksCache = new AwsAlbJwksCache();
    expect.assertions(1);
    return expect(
      jwksCache.getJwk(jwksUri, { header: { alg: "EC256" }, payload: {} })
    ).rejects.toThrow(JwtWithoutValidKidError);
  });


  test("ALB JWKS cache fetches URI one attempt at a time", async () => {
    /**
     * Test what happens when the the JWKS URI is requested multiple times in parallel
     * (e.g. in parallel promises). When this happens only 1 actual HTTPS request should
     * be made to the JWKS URI.
     */
    const fetcher = { fetch: jest.fn(async () => jwks) };
    const jwksCache = new AwsAlbJwksCache({
      fetcher,
    });
    const promise1 = jwksCache.getJwk(jwksUri, getDecomposedJwt());
    const promise2 = jwksCache.getJwk(jwksUri, getDecomposedJwt());
    expect.assertions(2);
    expect(promise1).toEqual(promise2);
    await Promise.all([promise1, promise2]);
    expect(fetcher.fetch).toHaveBeenCalledTimes(1);
  });

  test("ALB JWKS cache throws error if wait time did not yet pass", async () => {
    /**
     * Test what happens when the the JWKS URI would need te be fetched, but the last time
     * it was fetched, the requested JWK was not found in the JWKS. A new fetch of the JWKS URI will only
     * be executed after the wait time has lapsed. If the wait time did not lapse yet, an error should be thrown.
     * Test that this indeed happens. Also, test that requests for JWKs that are already in the cache, still
     * sucessfully return the JWK. After the wait time lapses, the JWKS URI may be fetched again.
     */
    const fetcher = { fetch: jest.fn(async () => jwks) };
    const waitSeconds = 0.5;
    const penaltyBox = new SimplePenaltyBox({ waitSeconds });
    const jwksCache = new AwsAlbJwksCache({
      fetcher,
      penaltyBox,
    });
    let error: Error | undefined = undefined;
    let wait: Promise<void> | undefined = undefined;

    // First: try to fetch JWK that does not exist
    try {
      await jwksCache.getJwk(jwksUri, getDecomposedJwt("otherkid"));
    } catch (err) {
      error = err as Error;
      wait = new Promise((resolve) => setTimeout(resolve, waitSeconds * 1000));
    }
    expect.assertions(5);
    expect(error).toBeInstanceOf(KidNotFoundInJwksError);

    // Then: try to fetch JWK that does not exist, this should throw an error
    try {
      await jwksCache.getJwk(jwksUri, getDecomposedJwt("otherkid"));
    } catch (err) {
      error = err as Error;
    }
    expect(error).toBeInstanceOf(WaitPeriodNotYetEndedJwkError);

    // Then: ensure we are still able to fetch cached JWK's without getting a wait error
    const jwk = await jwksCache.getJwk(jwksUri, getDecomposedJwt());
    expect(jwk).toEqual(jwk);

    // Then, ensure that after the wait period we can try again
    await wait!;
    try {
      await jwksCache.getJwk(jwksUri, getDecomposedJwt("otherkid"));
    } catch (err) {
      error = err as Error;
    }
    expect(error).toBeInstanceOf(KidNotFoundInJwksError);
    expect(fetcher.fetch).toHaveBeenCalledTimes(2);
    penaltyBox.release(jwksUri);
  });
});
