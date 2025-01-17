import { createPublicKey } from "crypto";
import {
  JwkInvalidKtyError,
  JwksNotAvailableInCacheError,
  JwtBaseError,
  JwtWithoutValidKidError,
} from "./error";
import { JwkWithKid, Jwks, JwksCache } from "./jwk";
import { JwtHeader, JwtPayload } from "./jwt-model";
import { Fetcher, SimpleFetcher } from "./https";
import { SimpleLruCache } from "./cache";
import { assertStringEquals } from "./assert";

const uuidRegex =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

interface DecomposedJwt {
  header: JwtHeader;
  payload: JwtPayload;
}

type JwksUri = string;

export class AlbUriError extends JwtBaseError {}

/**
 *
 * Security considerations:
 * It's important that the application protected by this library run in a secure environment. This application should be behind the ALB and deployed in a private subnet, or a public subnet but with no access from a untrusted network.
 * This security requierement is essential to be respected otherwise the application is exposed to several security risks. This class can be subject to a DoS attack if the attacker can control the kid.
 *
 */
export class AwsAlbJwksCache implements JwksCache {
  fetcher: Fetcher;
  // penaltyBox:PenaltyBox;

  private jwkCache: SimpleLruCache<JwksUri, JwkWithKid> = new SimpleLruCache(2);
  private fetchingJwks: Map<JwksUri, Promise<JwkWithKid>> = new Map();

  constructor(props?: {
    fetcher?: Fetcher;
    // penaltyBox?: PenaltyBox;
  }) {
    this.fetcher = props?.fetcher ?? new SimpleFetcher();
    // this.penaltyBox = props?.penaltyBox ?? new SimplePenaltyBox();
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
    return uuidRegex.test(kid);
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
        // await this.penaltyBox.wait(jwksUriWithKid, kid);
        const newFetchPromise = this.fetcher
          .fetch(jwksUriWithKid)
          .then((pem) => this.pemToJwk(kid, pem))
          .then((jwk) => {
            // this.penaltyBox.registerSuccessfulAttempt(jwksUriWithKid, kid);
            this.jwkCache.set(jwksUriWithKid, jwk);
            return jwk;
          })
          .catch((error) => {
            // this.penaltyBox.registerFailedAttempt(jwksUriWithKid, kid);
            throw error;
          })
          .finally(() => {
            this.fetchingJwks.delete(jwksUriWithKid);
          });

        this.fetchingJwks.set(jwksUriWithKid, newFetchPromise);

        return newFetchPromise;
      }
    }
  }

  private pemToJwk(kid: string, pem: ArrayBuffer): JwkWithKid {
    const jwk = createPublicKey({
      key: Buffer.from(pem),
      format: "pem",
      type: "spki",
    }).export({
      format: "jwk",
    });

    assertStringEquals("JWK kty", jwk.kty, "EC", JwkInvalidKtyError);

    return {
      kid: kid,
      use: "sig",
      ...jwk,
    } as JwkWithKid;
  }

  /**
   *
   * @param Ex: https://public-keys.auth.elb.eu-west-1.amazonaws.com
   * @param decomposedJwt
   * @returns
   */
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
        const jwkWithKid = jwk as JwkWithKid;
        const kid = jwk.kid;
        const jwksUriWithKid = this.expandWithKid(jwksUri, kid);
        this.jwkCache.set(jwksUriWithKid, jwkWithKid);
      } else {
        throw new Error("TODO");
      }
    } else {
      throw new Error("TODO");
    }
  }

  async getJwks(): Promise<Jwks> {
    throw new Error("Method not implemented.");
  }
}
