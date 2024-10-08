import { createPublicKey } from "crypto";
import {
  JwtBaseError,
  JwtWithoutValidKidError,
} from "./error";
import {
  JwkWithKid,
  Jwks,
  JwksCache,
  JwksParser,
  PenaltyBox,
  SimpleJwksCache,
  assertIsJwks,
} from "./jwk";
import { JwtHeader, JwtPayload } from "./jwt-model";

interface DecomposedJwt {
  header: JwtHeader;
  payload: JwtPayload;
}

const albJwksUriRegex =
  /https:\/\/public-keys.auth.elb.(?<region>[a-z0-9-]+).amazonaws.com\/(?<kid>[a-z0-9-]+)/;

export class AlbUriError extends JwtBaseError {}

const parseJwks: JwksParser = function (jwksBin: ArrayBuffer, jwksUri: string) {
  const match = jwksUri.match(albJwksUriRegex);
  if (!match || !match.groups?.kid) {
    throw new AlbUriError("Wrong URI for ALB public key");
  }
  const jwks = {
    keys: [
      {
        kid: match.groups.kid,
        use: "sig",
        ...createPublicKey({
          key: Buffer.from(jwksBin),
          format: "pem",
          type: "spki",
        }).export({
          format: "jwk",
        }),
      },
    ],
  };
  assertIsJwks(jwks);
  return jwks;
};

export class AwsAlbJwksCache implements JwksCache {
  simpleJwksCache: SimpleJwksCache;

  constructor(props?: { penaltyBox?: PenaltyBox }) {
    this.simpleJwksCache = new SimpleJwksCache({
      penaltyBox: props?.penaltyBox,
      jwksParser: parseJwks,
    });
  }

  /**
   * 
   * @param Ex: https://public-keys.auth.elb.eu-west-1.amazonaws.com
   * @param decomposedJwt 
   * @returns 
   */
  private expandWithKid(jwksUri: string, decomposedJwt: DecomposedJwt): string {
    const kid = this.getKid(decomposedJwt);
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

  public addJwks(): void {
    throw new Error("Method not implemented.");
  }

  async getJwks(): Promise<Jwks> {
    throw new Error("Method not implemented.");
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
