import cf from "cloudfront";

// aws-jwt-verify for CloudFront Functions (cloudfront-js-2.0, viewer request).
// Does what CognitoJwtVerifier / JwtVerifier do, in the same order: decompose the JWT,
// check iss, find the JWK by kid, check the JWK and alg, verify the signature, then check
// exp/nbf, aud (jwt) or token_use and client_id (cognito), scope and groups.
// JWKS cache: KeyValueStore, key "<kvsKeyPrefix><kid>" = the JWK as JSON. On a miss,
// one cf.fetch gets the JWKS from the issuer, an origin on this distribution.
// Fails closed: an invalid JWT is a 401, a JWKS it cannot get is a 503.
// Generate a configured copy with generate.ts, or edit CONFIG.

// BEGIN CONFIG
const CONFIG = {
  verifier: "cognito", // "cognito" (CognitoJwtVerifier) or "jwt" (JwtVerifier)
  issuers: [
    "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_example",
    "https://issuer-cognito-idp.us-east-1.amazonaws.com/us-east-1_example",
  ],
  jwksOriginId: "jwt-issuer", // the issuer's origin id on this distribution
  jwksPath: "/us-east-1_example/.well-known/jwks.json",
  tokenUse: "access", // cognito: "id", "access" or null (any)
  clientId: ["exampleclientid"], // cognito; null: do not check
  audience: null, // jwt; null: do not check
  scope: null,
  groups: null, // cognito
  graceSeconds: 0,
  kvsKeyPrefix: "jwk:",
};
// END CONFIG

const ALGS = {
  RS256: ["RSA", "RSASSA-PKCS1-v1_5", "SHA-256"],
  RS384: ["RSA", "RSASSA-PKCS1-v1_5", "SHA-384"],
  RS512: ["RSA", "RSASSA-PKCS1-v1_5", "SHA-512"],
  ES256: ["EC", "ECDSA", "SHA-256", "P-256"],
  ES384: ["EC", "ECDSA", "SHA-384", "P-384"],
  ES512: ["EC", "ECDSA", "SHA-512", "P-521"],
};
const B64URL = /^[A-Za-z0-9_-]+={0,2}$/;
const PREFIX = "x-jwt-";

function check(ok, name, message) {
  if (ok) return;
  const e = new Error(message);
  e.name = name;
  throw e;
}

function list(v) {
  return Array.isArray(v) ? v : [v];
}

function overlaps(actual, expected) {
  const x = list(expected);
  return (
    actual != null &&
    list(actual).some(function (a) {
      return x.indexOf(a) !== -1;
    })
  );
}

function isObject(v) {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

function parse(b64, what) {
  let v;
  try {
    v = JSON.parse(Buffer.from(b64, "base64url").toString("utf8"));
  } catch (e) {
    v = null;
  }
  check(isObject(v), "JwtParseError", what + " is not an object");
  return v;
}

function decompose(jwt) {
  const parts = jwt.split(".");
  check(
    parts.length === 3 && parts.every(B64URL.test.bind(B64URL)),
    "JwtParseError",
    "JWT does not consist of 3 base64url parts"
  );
  const header = parse(parts[0], "JWT header");
  const payload = parse(parts[1], "JWT payload");
  ["alg", "kid"].forEach(function (k) {
    check(
      header[k] === undefined || typeof header[k] === "string",
      "JwtParseError",
      "JWT header " + k + " claim is not a string"
    );
  });
  const types = { exp: 1, nbf: 1, iat: 1, iss: 0, sub: 0, scope: 0, jti: 0 };
  Object.keys(types).forEach(function (k) {
    const v = payload[k];
    check(
      v === undefined ||
        (types[k] ? Number.isFinite(v) : typeof v === "string"),
      "JwtParseError",
      "JWT payload " + k + " claim has the wrong type"
    );
  });
  const aud = payload.aud;
  check(
    aud === undefined ||
      list(aud).every(function (a) {
        return typeof a === "string";
      }),
    "JwtParseError",
    "JWT payload aud claim is not a string or array of strings"
  );
  return {
    header: header,
    payload: payload,
    input: parts[0] + "." + parts[1],
    signature: parts[2],
  };
}

function fetchError(message) {
  check(false, "FetchError", message);
}

// The JWK for this kid: from the KVS, else with the one network call.
async function getJwk(kid) {
  try {
    const kvsJwk = await cf.kvs().get(CONFIG.kvsKeyPrefix + kid, {
      format: "json",
    });
    if (isObject(kvsJwk) && kvsJwk.kid === kid) {
      return { jwk: kvsJwk, source: "kvs" };
    }
  } catch (e) {
    // A miss rejects: fetch the JWKS.
  }
  let res;
  let text;
  try {
    res = await cf.fetch(CONFIG.jwksPath, {
      originId: CONFIG.jwksOriginId,
      headers: { accept: "application/json" },
      includeBody: true,
    });
    if (res.ok) text = await res.text();
  } catch (e) {
    fetchError("JWKS fetch failed: " + e.name);
  }
  if (!res.ok) fetchError("JWKS fetch returned " + res.status);
  let jwks;
  try {
    jwks = JSON.parse(text);
  } catch (e) {
    jwks = null;
  }
  if (!isObject(jwks) || !Array.isArray(jwks.keys)) fetchError("Invalid JWKS");
  const jwk = jwks.keys.filter(function (k) {
    return isObject(k) && k.kid === kid;
  })[0];
  check(jwk, "KidNotFoundInJwksError", "JWK for kid not found in the JWKS");
  return { jwk: jwk, source: "fetch" };
}

function checkJwk(alg, jwk) {
  check(
    /^(RSA|EC)$/.test(jwk.kty),
    "JwkInvalidKtyError",
    "JWK kty not supported"
  );
  check(
    !jwk.use || jwk.use === "sig",
    "JwkInvalidUseError",
    "JWK use is not sig"
  );
  check(
    jwk.kty === "RSA" ? jwk.n && jwk.e : jwk.crv && jwk.x && jwk.y,
    "JwkValidationError",
    "JWK misses key material"
  );
  check(
    !jwk.alg || jwk.alg === alg,
    "JwtInvalidSignatureAlgorithmError",
    "JWT signature algorithm does not match the JWK"
  );
  const a = Object.prototype.hasOwnProperty.call(ALGS, alg) ? ALGS[alg] : null;
  check(
    a && a[0] === jwk.kty && (!a[3] || a[3] === jwk.crv),
    "JwtInvalidSignatureAlgorithmError",
    "JWT signature algorithm not supported for this JWK"
  );
  return a;
}

async function verifySignature(jwt, jwk, a) {
  const subtle = require("webcrypto").subtle;
  const rsa = a[0] === "RSA";
  const key = await subtle.importKey(
    "jwk",
    rsa
      ? { kty: "RSA", n: jwk.n, e: jwk.e }
      : { kty: "EC", crv: jwk.crv, x: jwk.x, y: jwk.y },
    rsa ? { name: a[1], hash: a[2] } : { name: a[1], namedCurve: a[3] },
    false,
    ["verify"]
  );
  const valid = await subtle.verify(
    { name: a[1], hash: a[2] },
    key,
    Buffer.from(jwt.signature, "base64url"),
    Buffer.from(jwt.input)
  );
  check(valid === true, "JwtInvalidSignatureError", "Invalid signature");
}

function checkClaims(p) {
  const now = Date.now() / 1000;
  const grace = CONFIG.graceSeconds;
  check(
    p.exp === undefined || p.exp + grace >= now,
    "JwtExpiredError",
    "Token expired"
  );
  check(
    p.nbf === undefined || p.nbf - grace <= now,
    "JwtNotBeforeError",
    "Token not valid yet"
  );
  check(
    CONFIG.audience === null || overlaps(p.aud, CONFIG.audience),
    "JwtInvalidAudienceError",
    "Audience not allowed"
  );
  check(
    CONFIG.scope === null ||
      (typeof p.scope === "string" &&
        overlaps(p.scope.split(" "), CONFIG.scope)),
    "JwtInvalidScopeError",
    "Scope not allowed"
  );
  if (CONFIG.verifier !== "cognito") return;
  check(
    CONFIG.groups === null || overlaps(p["cognito:groups"], CONFIG.groups),
    "CognitoJwtInvalidGroupError",
    "Cognito group not allowed"
  );
  check(
    (p.token_use === "id" || p.token_use === "access") &&
      (CONFIG.tokenUse === null || p.token_use === CONFIG.tokenUse),
    "CognitoJwtInvalidTokenUseError",
    "Token use not allowed"
  );
  const clientId = p.token_use === "id" ? p.aud : p.client_id;
  check(
    CONFIG.clientId === null ||
      (typeof clientId === "string" &&
        list(CONFIG.clientId).indexOf(clientId) !== -1),
    "CognitoJwtInvalidClientIdError",
    "Client ID not allowed"
  );
}

// Resolves to { payload, source }, or throws an error named like the aws-jwt-verify class.
async function verify(token) {
  const jwt = decompose(token);
  const kid = jwt.header.kid;
  check(
    CONFIG.issuers.indexOf(jwt.payload.iss) !== -1,
    "JwtInvalidIssuerError",
    "Issuer not allowed"
  );
  check(
    kid && kid.length <= 256,
    "JwtWithoutValidKidError",
    "JWT header has no valid kid"
  );
  // KVS and the call first: no network call is allowed after webcrypto.
  const found = await getJwk(kid);
  const a = checkJwk(jwt.header.alg, found.jwk);
  await verifySignature(jwt, found.jwk, a);
  checkClaims(jwt.payload);
  return { payload: jwt.payload, source: found.source };
}

function deny(status, error) {
  const headers = {
    "content-type": { value: "application/json" },
    "cache-control": { value: "no-store" },
  };
  headers[PREFIX + "error"] = { value: error };
  if (status === 401) {
    headers["www-authenticate"] = { value: 'Bearer error="invalid_token"' };
  }
  return {
    statusCode: status,
    statusDescription: status === 401 ? "Unauthorized" : "Service Unavailable",
    headers: headers,
    body: JSON.stringify({ error: error }),
  };
}

async function handler(event) {
  const request = event.request;
  const headers = request.headers;
  // Never pass on x-jwt-* headers from the viewer.
  ["sub", "client-id", "jwks"].forEach(function (h) {
    delete headers[PREFIX + h];
  });
  const m = /^Bearer +(\S+)$/i.exec(
    headers.authorization ? headers.authorization.value : ""
  );
  if (!m) return deny(401, "JwtParseError");
  let result;
  try {
    result = await verify(m[1]);
  } catch (e) {
    const name = String(e && e.name);
    if (name === "FetchError") return deny(503, name + ": " + e.message);
    if (/^(Jwt|Jwk|Kid|Cognito)/.test(name)) return deny(401, name);
    // Anything else (no webcrypto, a key it cannot import): cannot verify, fail closed.
    return deny(503, "VerificationError: " + name);
  }
  const p = result.payload;
  const clientId = p.client_id || (typeof p.aud === "string" ? p.aud : "");
  if (p.sub) headers[PREFIX + "sub"] = { value: p.sub };
  if (clientId) headers[PREFIX + "client-id"] = { value: clientId };
  headers[PREFIX + "jwks"] = { value: result.source };
  return request;
}
