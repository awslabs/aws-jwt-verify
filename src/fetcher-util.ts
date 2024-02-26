import { JwtBaseError, JwtWithoutValidKidError, KidNotFoundInJwksError } from "./error";
import { JsonFetcher, SimpleJsonFetcher } from "./https";
import { JwkWithKid, Jwks, JwksCache, PenaltyBox, SimpleJwksCache } from "./jwk";
import { DecomposedJwt } from "./jwt";
import crypto from "crypto";

type AwsAlbJwks = string;

// https://public-keys.auth.elb.eu-west-1.amazonaws.com/575d530c-54b0-43c3-8ce0-e7ed4dccdb8f
const albRegex = /https:\/\/public-keys.auth.elb.(?<region>[a-z0-9-]+).amazonaws.com\/(?<kid>[a-z0-9-]+)/g;

export class AlbUriError extends JwtBaseError {}

export class AwsAlbJwksFetcher implements JsonFetcher {

  private fetcher = new SimpleJsonFetcher();

  public async fetch(...params: Parameters<JsonFetcher["fetch"]>) {
    const uri = params[0];
    const match = uri.match(albRegex);
    if(!match){
      throw new AlbUriError(
        "Wrong URI for ALB public key"
      );
    }
    return this.fetcher.fetch(...params).then((response) => {
      return {
        keys: [
          {
            kid: match.groups?.kid!,
            kty: "RSA",
            use: "sig",
            ...crypto.createPublicKey(response as AwsAlbJwks).export({
              format: "jwk",
            }),
          },
        ],
      };
    });
  }
}

const KID_URI_VARIABLE = "{kid}";

export class AwsAlbJwksCache implements JwksCache {

  private simpleJwksCache: SimpleJwksCache;

  constructor(props?: { penaltyBox?: PenaltyBox; fetcher?: JsonFetcher }) {
    this.simpleJwksCache = new SimpleJwksCache(
      { penaltyBox: props?.penaltyBox, fetcher: props?.fetcher ?? new AwsAlbJwksFetcher() }
    );
  }

  private expandWithKid(jwksUri: string,decomposedJwt: DecomposedJwt):string{
    const kid = this.getKid(decomposedJwt);
    if(jwksUri.indexOf(KID_URI_VARIABLE)<0){
      throw new KidNotFoundInJwksError(
        "kid not found in URI"
      );
    }
    return jwksUri.replace(KID_URI_VARIABLE,encodeURIComponent(kid));
  }

  private getKid(decomposedJwt: DecomposedJwt):string{
    if (typeof decomposedJwt.header.kid !== "string") {
      throw new JwtWithoutValidKidError(
        "JWT header does not have valid kid claim"
      );
    }
    return decomposedJwt.header.kid;
  }

  addJwks(): void {
    throw new Error("Method not implemented.");
  }

  getJwks(): Promise<Jwks> {
      throw new Error("Method not implemented.");
  }

  public getCachedJwk(
    jwksUri: string,
    decomposedJwt: DecomposedJwt
  ): JwkWithKid {
    const jwksUriExpanded = this.expandWithKid(jwksUri,decomposedJwt);
    return this.simpleJwksCache.getCachedJwk(jwksUriExpanded,decomposedJwt);
  }

  public async getJwk(
    jwksUri: string,
    decomposedJwt: DecomposedJwt
  ): Promise<JwkWithKid> {
    const jwksUriExpanded = this.expandWithKid(jwksUri,decomposedJwt);
    return this.simpleJwksCache.getJwk(jwksUriExpanded,decomposedJwt);
  }


}
