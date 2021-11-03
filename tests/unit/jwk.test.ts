import {
  fetchJwks,
  fetchJwk,
  SimpleJwksCache,
  assertIsJwks,
  SimplePenaltyBox,
  assertIsJwk,
  isJwks,
  PenaltyBox,
} from "../../src/jwk";
import {
  JwtWithoutValidKidError,
  WaitPeriodNotYetEndedJwkError,
  KidNotFoundInJwksError,
  JwksValidationError,
  JwkValidationError,
} from "../../src/error";
import { JsonFetcher } from "../../src/https";
import {
  mockHttpsUri,
  generateKeyPair,
  disallowAllRealNetworkTraffic,
  allowAllRealNetworkTraffic,
} from "./test-util";

describe("unit tests jwk", () => {
  const jwksUri = "https://example.com/keys/jwks.json";
  let keypair: ReturnType<typeof generateKeyPair>;
  const getDecomposedJwt = (kid?: string) => ({
    header: {
      alg: "RS256",
      kid: kid ?? keypair.jwk.kid,
    },
    payload: {},
  });
  beforeAll(() => {
    keypair = generateKeyPair();
    disallowAllRealNetworkTraffic();
  });
  afterAll(() => {
    allowAllRealNetworkTraffic();
  });

  test("Fetch JWKS works", () => {
    mockHttpsUri(jwksUri, { responsePayload: JSON.stringify(keypair.jwks) });
    expect.assertions(1);
    return expect(fetchJwks(jwksUri)).resolves.toEqual(keypair.jwks);
  });

  test("Fetch JWK works", () => {
    mockHttpsUri(jwksUri, { responsePayload: JSON.stringify(keypair.jwks) });
    expect.assertions(1);
    return expect(fetchJwk(jwksUri, getDecomposedJwt())).resolves.toEqual(
      keypair.jwk
    );
  });

  test("Fetch JWK error flow: kid empty", () => {
    expect.assertions(1);
    return expect(
      fetchJwk(jwksUri, { header: { alg: "RS256" }, payload: {} })
    ).rejects.toThrow(JwtWithoutValidKidError);
  });

  test("Fetch JWK error flow: kid not found", () => {
    /**
     * Test what happens when a JWK is requested that is not found in the JWKS (by key ID)
     * This should raise an error
     */
    mockHttpsUri(jwksUri, { responsePayload: JSON.stringify(keypair.jwks) });
    expect.assertions(1);
    return expect(
      fetchJwk(jwksUri, getDecomposedJwt("kiddoesnotexist"))
    ).rejects.toThrow(KidNotFoundInJwksError);
  });

  test("Validate JWKS error flow: no jwks", () => {
    expect(() => assertIsJwks("")).toThrow("JWKS empty");
  });

  test("Validate JWKS error flow: jwks is not an object", () => {
    expect(() => assertIsJwks("foo")).toThrow("JWKS should be an object");
  });

  test("Simple JWKS cache returns JWK", () => {
    const jwksCache = new SimpleJwksCache({
      fetcher: { fetch: async () => keypair.jwks as any },
    });
    expect.assertions(1);
    return expect(
      jwksCache.getJwk(jwksUri, getDecomposedJwt())
    ).resolves.toEqual(keypair.jwk);
  });

  test("Simple JWKS cache returns cached JWK", () => {
    const jwksCache = new SimpleJwksCache({
      fetcher: { fetch: async () => keypair.jwks as any },
    });
    jwksCache.addJwks(jwksUri, keypair.jwks);
    expect(jwksCache.getCachedJwk(jwksUri, getDecomposedJwt())).toEqual(
      keypair.jwk
    );
  });

  test("Simple JWKS cache error flow: kid empty", () => {
    const jwksCache = new SimpleJwksCache();
    expect.assertions(1);
    return expect(
      jwksCache.getJwk(jwksUri, { header: { alg: "RS256" }, payload: {} })
    ).rejects.toThrow(JwtWithoutValidKidError);
  });

  test("Simple JWKS cache error flow: JWK not cached", () => {
    const jwksCache = new SimpleJwksCache({
      fetcher: { fetch: async () => keypair.jwks as any },
    });
    jwksCache.addJwks(jwksUri, keypair.jwks);
    expect(() =>
      jwksCache.getCachedJwk(
        "https://example.com/notcached/keys.json",
        getDecomposedJwt()
      )
    ).toThrow(
      "JWKS for uri https://example.com/notcached/keys.json not yet available in cache"
    );
    expect(() =>
      jwksCache.getCachedJwk(jwksUri, getDecomposedJwt("otherkid"))
    ).toThrow("JWK for kid otherkid not found in the JWKS");
  });

  test("Simple JWKS cache fetches URI one attempt at a time", async () => {
    /**
     * Test what happens when the the JWKS URI is requested multiple times in parallel
     * (e.g. in parallel promises). When this happens only 1 actual HTTPS request should
     * be made to the JWKS URI.
     */
    const fetcher = { fetch: jest.fn(async () => keypair.jwks as any) };
    const jwksCache = new SimpleJwksCache({
      fetcher,
    });
    const promise1 = jwksCache.getJwk(jwksUri, getDecomposedJwt());
    const promise2 = jwksCache.getJwk(jwksUri, getDecomposedJwt());
    expect.assertions(2);
    expect(promise1).toEqual(promise2);
    await Promise.all([promise1, promise2]);
    expect(fetcher.fetch).toHaveBeenCalledTimes(1);
  });

  test("Simple JWKS cache throws error if wait time did not yet pass", async () => {
    /**
     * Test what happens when the the JWKS URI would need te be fetched, but the last time
     * it was fetched, the requested JWK was not found in the JWKS. A new fetch of the JWKS URI will only
     * be executed after the wait time has lapsed. If the wait time did not lapse yet, an error should be thrown.
     * Test that this indeed happens. Also, test that requests for JWKs that are already in the cache, still
     * sucessfully return the JWK. After the wait time lapses, the JWKS URI may be fetched again.
     */
    const fetcher = { fetch: jest.fn(async () => keypair.jwks as any) };
    const waitSeconds = 0.5;
    const penaltyBox = new SimplePenaltyBox({ waitSeconds });
    const jwksCache = new SimpleJwksCache({
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

    // Then: try to fetch other JWK that does not exist, this should throw an error
    try {
      await jwksCache.getJwk(jwksUri, getDecomposedJwt("otherkid2"));
    } catch (err) {
      error = err as Error;
    }
    expect(error).toBeInstanceOf(WaitPeriodNotYetEndedJwkError);

    // Then: ensure we are still able to fetch cached JWK's without getting a wait error
    const jwk = await jwksCache.getJwk(jwksUri, getDecomposedJwt());
    expect(jwk).toEqual(keypair.jwk);

    // Then, ensure that after the wait period we can try again
    await wait!;
    try {
      await jwksCache.getJwk(jwksUri, getDecomposedJwt("otherkid"));
    } catch (err) {
      error = err as Error;
    }
    expect(error).toBeInstanceOf(KidNotFoundInJwksError);
    expect(fetcher.fetch).toHaveBeenCalledTimes(2);
    jwksCache.penaltyBox.release(jwksUri);
  });

  describe("validate", () => {
    describe("JWK", () => {
      test("empty JWK", () => {
        const jwk = "";
        const statement = () => assertIsJwk(jwk);
        expect(statement).toThrow("JWK empty");
        expect(statement).toThrow(JwkValidationError);
      });
      test("JWK is not an object", () => {
        const jwk = "foobar";
        const statement = () => assertIsJwk(jwk);
        expect(statement).toThrow("JWK should be an object");
        expect(statement).toThrow(JwkValidationError);
      });
      test("JWK optional field alg is not a string", () => {
        const jwk = {
          kty: "RSA",
          use: "sig",
          kid: "nOo3ZDrODXEK1jKWhXslHR_KXEq",
          n: "1",
          e: "2",
          alg: 123,
        };
        const statement = () => assertIsJwk(jwk);
        expect(statement).toThrow("JWK alg should be a string");
        expect(statement).toThrow(JwkValidationError);
      });
    });
    describe("JWKS", () => {
      test("no keys", () => {
        const jwks = {};
        const statement = () => assertIsJwks(jwks);
        expect(statement).toThrow("JWKS does not include keys");
        expect(statement).toThrow(JwksValidationError);
      });
      test("keys not an array", () => {
        const jwks = { keys: 123 };
        const statement = () => assertIsJwks(jwks);
        expect(statement).toThrow("JWKS keys should be an array");
        expect(statement).toThrow(JwksValidationError);
      });
      test("not a valid jwks", () => {
        const jwks = {};
        expect(isJwks(jwks)).toBe(false);
      });
      test("is a valid jwks", () => {
        const jwks = { keys: [] };
        expect(isJwks(jwks)).toBe(true);
      });
    });
  });

  describe("customize JWKS cache", () => {
    test("SimpleJwksCache with custom penaltyBox and fetcher", async () => {
      class CustomPenaltyBox implements PenaltyBox {
        public wait = jest.fn(async (_jwksUri: string, _kid: string) => {
          // This is intentional
        });
        public release = jest.fn((_jwksUri: string, _kid?: string) => {
          // This is intentional
        });
        public registerFailedAttempt = jest.fn(
          (_jwksUri: string, _kid: string) => {
            // This is intentional
          }
        );
        public registerSuccessfulAttempt = jest.fn(
          (_jwksUri: string, _kid: string) => {
            // This is intentional
          }
        );
      }
      class CustomJsonFetcher implements JsonFetcher {
        public fetch = jest.fn(async (_uri: string) => {
          return keypair.jwks as any;
        });
      }
      const penaltyBox = new CustomPenaltyBox();
      const fetcher = new CustomJsonFetcher();
      const cache = new SimpleJwksCache({ penaltyBox, fetcher });
      let fetchedJwk = await cache.getJwk(jwksUri, getDecomposedJwt());
      expect(fetcher.fetch).toHaveBeenCalledWith(jwksUri);
      expect(fetchedJwk).toEqual(keypair.jwk);
      fetcher.fetch.mockClear();
      fetchedJwk = await cache.getJwk(jwksUri, getDecomposedJwt()); // Should get from cache and NOT fetch
      expect(fetcher.fetch).toHaveBeenCalledTimes(0);
      expect(fetchedJwk).toEqual(keypair.jwk);
    });
  });
});
