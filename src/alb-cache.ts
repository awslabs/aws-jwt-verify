import {
  AlbJwksNotExposedError,
  JwksNotAvailableInCacheError,
  JwksValidationError,
  JwkValidationError,
  JwtWithoutValidKidError,
} from "./error.js";
import { JwkWithKid, Jwks, JwksCache } from "./jwk.js";
import { Fetcher, SimpleFetcher } from "./https.js";
import { SimpleLruCache } from "./cache.js";
import { JwtHeader, JwtPayload } from "./jwt-model.js";
import { nodeWebCompat } from "#node-web-compat";

const UUID_REGEXP =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

interface DecomposedJwt {
  header: JwtHeader;
  payload: JwtPayload;
}

type JwksUri = string;

export class AlbJwksCache implements JwksCache {
  fetcher: Fetcher;

  private jwkCache: SimpleLruCache<JwksUri, JwkWithKid> = new SimpleLruCache(2);
  private fetchingJwks: Map<JwksUri, Promise<JwkWithKid>> = new Map();

  constructor(props?: { fetcher?: Fetcher }) {
    this.fetcher = props?.fetcher ?? new SimpleFetcher();
  }

  private expandWithKid(jwksUri: string, kid: string): string {
    return `${jwksUri}/${encodeURIComponent(kid)}`;
  }

  private getKid(decomposedJwt: DecomposedJwt): string {
    const kid = decomposedJwt.header.kid;
    if (typeof kid !== "string" || !this.isValidAlbKid(kid)) {
      throw new JwtWithoutValidKidError(
        "JWT header does not have valid kid claim"
      );
    }
    return kid;
  }

  private isValidAlbKid(kid: string): boolean {
    return UUID_REGEXP.test(kid);
  }

  public async getJwk(
    jwksUri: string,
    decomposedJwt: DecomposedJwt
  ): Promise<JwkWithKid> {
    const kid = this.getKid(decomposedJwt);
    const jwksUriWithKid = this.expandWithKid(jwksUri, kid);
    const jwk = this.jwkCache.get(jwksUriWithKid);
    if (jwk) {
      //cache hit
      return jwk;
    } else {
      //cache miss
      const fetchPromise = this.fetchingJwks.get(jwksUriWithKid);
      if (fetchPromise) {
        return fetchPromise;
      } else {
        const newFetchPromise = this.fetcher
          .fetch(jwksUriWithKid)
          .then((pem) => this.pemToJwk(kid, pem))
          .then((jwk) => {
            this.jwkCache.set(jwksUriWithKid, jwk);
            return jwk;
          })
          .finally(() => {
            this.fetchingJwks.delete(jwksUriWithKid);
          });

        this.fetchingJwks.set(jwksUriWithKid, newFetchPromise);

        return newFetchPromise;
      }
    }
  }

  private async pemToJwk(kid: string, pem: ArrayBuffer): Promise<JwkWithKid> {
    const jwk = await nodeWebCompat.transformPemToJwk(pem);
    return {
      ...jwk,
      use: "sig",
      alg: "ES256",
      kid: kid,
    } as JwkWithKid;
  }

  public getCachedJwk(
    jwksUri: string,
    decomposedJwt: DecomposedJwt
  ): JwkWithKid {
    const kid = this.getKid(decomposedJwt);
    const jwksUriWithKid = this.expandWithKid(jwksUri, kid);
    const jwk = this.jwkCache.get(jwksUriWithKid);
    if (jwk) {
      return jwk;
    } else {
      throw new JwksNotAvailableInCacheError(
        `JWKS for uri ${jwksUri} not yet available in cache`
      );
    }
  }

  public addJwks(jwksUri: string, jwks: Jwks): void {
    if (jwks.keys.length === 1) {
      const jwk = jwks.keys[0];
      if (jwk.kid) {
        const jwksUriWithKid = this.expandWithKid(jwksUri, jwk.kid);
        this.jwkCache.set(jwksUriWithKid, jwk as JwkWithKid);
      } else {
        throw new JwkValidationError("JWK does not have a kid");
      }
    } else {
      throw new JwksValidationError("Only one JWK is expected in the JWKS");
    }
  }

  async getJwks(): Promise<Jwks> {
    throw new AlbJwksNotExposedError("AWS ALB does not expose JWKS");
  }
}
