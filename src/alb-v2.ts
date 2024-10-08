import { createPublicKey } from "crypto";
import {
  JwksNotAvailableInCacheError,
  JwtBaseError,
  JwtWithoutValidKidError,
} from "./error";
import {
  JwkWithKid,
  Jwks,
  JwksCache,
} from "./jwk";
import { JwtHeader, JwtPayload } from "./jwt-model";
import { Fetcher, SimpleFetcher } from "./https";
import { SimpleLruCache } from "./cache";

interface DecomposedJwt {
  header: JwtHeader;
  payload: JwtPayload;
}

type JwksUri = string;

type CacheValue = {
  jwk?:JwkWithKid;
  promise:Promise<JwkWithKid>; 
}

export class AlbUriError extends JwtBaseError {}

export class AwsAlbJwksCache implements JwksCache {

  fetcher: Fetcher;

  private jwkCache: SimpleLruCache<JwksUri,CacheValue> = new SimpleLruCache(2);

  constructor(props?: {
    fetcher?: Fetcher;
  }) {
    this.fetcher = props?.fetcher ?? new SimpleFetcher();
  }


  /**
   * 
   * @param jwksUri should be a template URI with the kid expression. Ex: https://public-keys.auth.elb.eu-west-1.amazonaws.com/{kid}
   * @param decomposedJwt 
   * @returns 
   */
  private expandWithKid(jwksUri: string, kid: string): string {
    return `${jwksUri}/${encodeURIComponent(kid)}`;
  }

  private getKid(decomposedJwt: DecomposedJwt): string {
    if (typeof decomposedJwt.header.kid !== "string") {
      throw new JwtWithoutValidKidError(
        "JWT header does not have valid kid claim"
      );
    }
    return decomposedJwt.header.kid;
  }

  public async getJwk(
    jwksUri: string,
    decomposedJwt: DecomposedJwt
  ): Promise<JwkWithKid> {
    const kid = this.getKid(decomposedJwt);
    const jwksUriWithKid = this.expandWithKid(jwksUri, kid);
    const cacheValue = this.jwkCache.get(jwksUriWithKid);
    if(cacheValue){
      //cache hit
      if(cacheValue.jwk){
        return cacheValue.jwk;
      }else{
        return cacheValue.promise;
      }
    }else{
      //cache miss
      const cacheValue:CacheValue = {
        promise:this.fetcher
          .fetch(jwksUri)
          .then(pem =>this.pemToJwk(kid,pem))
          .then(jwk=>cacheValue.jwk = jwk)
      }
      
      const jwkPromise = cacheValue.promise;
      //TODO error and retry
      this.jwkCache.set(jwksUriWithKid,cacheValue);
      return jwkPromise;
    }
  }
  
  private pemToJwk(kid:string, pem:ArrayBuffer):JwkWithKid{
    const jwk = createPublicKey({
      key: Buffer.from(pem),
      format: "pem",
      type: "spki",
    }).export({
      format: "jwk",
    });

    if(!jwk.kty){
      throw new Error("todo");
    }

    return { 
      kid: kid,
      use: "sig",
      ...jwk,
    } as JwkWithKid
  }

  public getCachedJwk(
    jwksUri: string,
    decomposedJwt: DecomposedJwt
  ): JwkWithKid {
    const kid = this.getKid(decomposedJwt);
    const jwksUriWithKid = this.expandWithKid(jwksUri, kid);
    const cacheValue = this.jwkCache.get(jwksUriWithKid);
    if(cacheValue?.jwk){
      return cacheValue.jwk;
    }else{
      throw new JwksNotAvailableInCacheError(
        `JWKS for uri ${jwksUri} not yet available in cache`
      );
    }
  }

  public addJwks(jwksUri: string, jwks: Jwks): void {
    if(jwks.keys.length===1){
      const jwk = jwks.keys[0];
      if(jwk.kid){
        const jwkWithKid = jwk as JwkWithKid;
        const kid = jwk.kid;
        const jwksUriWithKid = this.expandWithKid(jwksUri, kid);
        this.jwkCache.set(jwksUriWithKid,{
          jwk:jwkWithKid,
          promise:Promise.resolve(jwkWithKid)
        });
      }else{
        throw new Error("TODO");
      }
    }else{
      throw new Error("TODO");
    }
  }

  async getJwks(): Promise<Jwks> {
    throw new Error("Method not implemented.");
  }

}
