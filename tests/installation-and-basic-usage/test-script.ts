import { JwtRsaVerifier } from "aws-jwt-verify";
import { generateKeyPair, signJwt } from "../unit/test-util";
import { SimpleJwksCache } from "aws-jwt-verify/jwk";
import { SimpleJsonFetcher } from "aws-jwt-verify/https";
import { createServer } from "https";
import { readFileSync } from "fs";
import { join } from "path";

const issuer = "https://example.com/idp";
const audience = "myaudience";
const keypair = generateKeyPair();
const validJwt = signJwt(
  { kid: keypair.jwk.kid },
  { hello: "world", iss: issuer, aud: audience },
  keypair.privateKey
);
const invalidJwt = signJwt({}, { hello: "world" }, keypair.privateKey, false);
const verifier = JwtRsaVerifier.create(
  {
    issuer: "https://example.com/idp",
    jwksUri: "https://localhost:8443/idp/jwks.json",
    audience,
  },
  {
    jwksCache: new SimpleJwksCache({
      fetcher: new SimpleJsonFetcher({
        defaultRequestOptions: {
          rejectUnauthorized: false, // ignore SSL errors because we use a self-signed cert for the test
        } as unknown, // cast to unknown because the Node.js types are not complete
      }),
    }),
  }
);

function startJwksServer() {
  const options = {
    key: readFileSync(join(__dirname, "key.pem")),
    cert: readFileSync(join(__dirname, "cert.pem")),
  };
  let induceTcpError = true; // induce TCP errors to test retry mechanism
  const server = createServer(options, (req, res) => {
    if (induceTcpError) {
      req.destroy();
    } else {
      res.setHeader("Content-Type", "application/json");
      res.write(JSON.stringify(keypair.jwks));
      res.end();
    }
    induceTcpError = !induceTcpError; // toggle value
  }).listen({
    port: 8443,
  });
  return server;
}

function syncTest() {
  verifier.verifySync(validJwt);
  let error: Error;
  try {
    verifier.verifySync(invalidJwt);
  } catch (err) {
    error = err;
  }
  if (!error) {
    throw new Error("Expected JWT to not verify successfully");
  }
}

async function asyncTest() {
  await verifier.verify(validJwt);
  let error: Error;
  try {
    await verifier.verify(invalidJwt);
  } catch (err) {
    error = err;
  }
  if (!error) {
    throw new Error("Expected JWT to not verify successfully");
  }
}

async function main() {
  console.log("Running some basic jwt verification tests ...");
  const jwksServer = startJwksServer();
  try {
    await asyncTest();
    syncTest(); // because we run this after the async verify, the JWKS should have been loaded into the cache
  } finally {
    jwksServer.close();
  }

  console.log("TEST SUCCESS");
}

main().catch((err) => {
  console.error(err);
  console.error("TEST FAILED");
  process.exit(1);
});
