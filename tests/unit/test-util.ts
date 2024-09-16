import nock from "nock";
import { URL } from "url";
export { signJwt } from "../util/util";
export { generateKeyPair } from "../util/util";

export function disallowAllRealNetworkTraffic() {
  nock.disableNetConnect();
}

export function allowAllRealNetworkTraffic() {
  nock.enableNetConnect();
}

export function throwOnUnusedMocks() {
  if (nock.activeMocks().length) {
    throw new Error(
      `HTTP mocks still active: ${nock.activeMocks().join(", ")}`
    );
  }
}

export function mockHttpsUri(
  uri: string,
  propsOrError:
    | {
        responseStatus?: number;
        responseHeaders?: { [key: string]: string };
        responsePayload?: string | Buffer | ArrayBuffer;
        delayBody?: number;
      }
    | Error
) {
  const url = new URL(uri);
  const scope = nock(`https://${url.host}`).get(`${url.pathname}${url.search}`);
  if (propsOrError instanceof Error) {
    scope.replyWithError(propsOrError);
  } else {
    if (propsOrError.delayBody) {
      scope.delayBody(propsOrError.delayBody);
    }
    scope.reply(
      propsOrError.responseStatus,
      propsOrError.responsePayload,
      propsOrError.responseHeaders
    );
  }
  return scope;
}
