import {
  JwtBaseError,
  JwtWithoutValidKidError,
  KidNotFoundInJwksError,
} from "./error";
import { JsonFetcher, SimpleBufferFetcher } from "./https";
import {
  JwkWithKid,
  Jwks,
  JwksCache,
  PenaltyBox,
  SimpleJwksCache,
} from "./jwk";
import crypto from "crypto";
import { JwtHeader, JwtPayload } from "./jwt-model";

interface DecomposedJwt {
  header: JwtHeader;
  payload: JwtPayload;
}

const albRegex =
  /https:\/\/public-keys.auth.elb.(?<region>[a-z0-9-]+).amazonaws.com\/(?<kid>[a-z0-9-]+)/;

export class AlbUriError extends JwtBaseError {}

type FetchRequestOptions = Record<string, unknown>;

export class AwsAlbJwksFetcher implements JsonFetcher {
  private fetcher;

  constructor(props?: { defaultRequestOptions?: FetchRequestOptions }) {
    this.fetcher = new SimpleBufferFetcher(props);
  }

  public async fetch(
    uri: string,
    requestOptions?: FetchRequestOptions,
    data?: Buffer
  ) {
    return this.fetcher.fetch(uri, requestOptions, data).then((response) => {
      const match = uri.match(albRegex);
      if (!match) {
        throw new AlbUriError("Wrong URI for ALB public key");
      }

      return {
        keys: [
          {
            kid: match.groups!.kid!,
            use: "sig",
            ...crypto.createPublicKey(response).export({
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
    this.simpleJwksCache = new SimpleJwksCache({
      penaltyBox: props?.penaltyBox,
      fetcher: props?.fetcher ?? new AwsAlbJwksFetcher(),
    });
  }

  private expandWithKid(jwksUri: string, decomposedJwt: DecomposedJwt): string {
    const kid = this.getKid(decomposedJwt);
    if (jwksUri.indexOf(KID_URI_VARIABLE) < 0) {
      throw new KidNotFoundInJwksError("kid not found in URI");
    }
    return jwksUri.replace(KID_URI_VARIABLE, encodeURIComponent(kid));
  }

  private getKid(decomposedJwt: DecomposedJwt): string {
    if (typeof decomposedJwt.header.kid !== "string") {
      throw new JwtWithoutValidKidError(
        "JWT header does not have valid kid claim"
      );
    }
    return decomposedJwt.header.kid;
  }

  public addJwks(): void {
    throw new Error("Method not implemented.");
  }

  async getJwks(): Promise<Jwks> {
    throw new Error("Method not implemented.");
  }

  public getCachedJwk(
    jwksUri: string,
    decomposedJwt: DecomposedJwt
  ): JwkWithKid {
    const jwksUriExpanded = this.expandWithKid(jwksUri, decomposedJwt);
    return this.simpleJwksCache.getCachedJwk(jwksUriExpanded, decomposedJwt);
  }

  public async getJwk(
    jwksUri: string,
    decomposedJwt: DecomposedJwt
  ): Promise<JwkWithKid> {
    const jwksUriExpanded = this.expandWithKid(jwksUri, decomposedJwt);
    return this.simpleJwksCache.getJwk(jwksUriExpanded, decomposedJwt);
  }
}
