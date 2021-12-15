#!/usr/bin/env node

import { verifyJwt, verifyJwtSync } from "../dist/esm/jwt-rsa.js";
import { decomposeJwt } from "../dist/esm/jwt.js";
const [_executable, program, command, jwt, ...opts] = process.argv;

function parseCommandLineOptions(opts) {
  const flagOpts = ["json"];
  const parsed = {};
  while (opts.length) {
    let opt = opts.splice(0, 1)[0];
    if (opt.startsWith("--")) {
      opt = opt.slice(2);
      if (flagOpts.includes(opt)) {
        parsed.opt = true;
        continue;
      }
      const optValue = opts.splice(0, 1)[0];
      if (!optValue) {
        throw new Error(`Provide value for option: ${opt}`);
      }
      parsed.opt = optValue;
    }
  }
  return parsed;
}

async function main() {
  const options = parseCommandLineOptions(opts);
  switch (command) {
    case "view":
      if (jwt === undefined)
        exitWithError("Error: JWT must be provided as first argument");
      break;
    case "verify":
      if (jwt === undefined)
        exitWithError("Error: JWT must be provided as first argument");
      break;
    case "--help":
      usage();
      break;
    default:
      usage();
  }
}

function viewJwt(jwt, options) {
  const { header, payload, signatureB64 } = decomposeJwt(jwt);
  if (options?.json) {
    console.log(JSON.stringify({ header, payload, signatureB64 }));
    return;
  }
  const title = "Decomposed JWT";
  const headerTitle = "header:";
  const payloadTitle = "payload:";
  const signatureTitle = "signature:";
  const longestKeyLength = getLongestKeyLength(
    header,
    payload,
    headerTitle,
    title
  );
  console.log();
  console.log(`${spaces(longestKeyLength - title.length + 1)}${title}`);
  console.log(`${spaces(longestKeyLength - title.length + 1)}‾‾‾‾‾‾‾‾‾‾‾‾‾‾`);
  console.log(
    `${spaces(longestKeyLength - headerTitle.length + 1)}${headerTitle}`
  );
  console.log(`${spaces(longestKeyLength - headerTitle.length + 1)}‾‾‾‾‾‾‾`);
  console.log(displayKeys(header, longestKeyLength));
  console.log();
  console.log(
    `${spaces(longestKeyLength - payloadTitle.length + 1)}${payloadTitle}`
  );
  console.log(`${spaces(longestKeyLength - payloadTitle.length + 1)}‾‾‾‾‾‾‾‾`);
  console.log(displayKeys(payload, longestKeyLength));
  console.log();
  console.log(
    `${spaces(longestKeyLength - signatureTitle.length + 1)}${signatureTitle}`
  );
  console.log(
    `${spaces(longestKeyLength - signatureTitle.length + 1)}‾‾‾‾‾‾‾‾‾‾`
  );
  console.log(signatureB64);
  console.log();
}

async function verify(jwt, options) {
  const { payload } = decomposeJwt(jwt);
  if (options.userPoolId) {
    throw new Error("Cognito verif not implemented");
  }
  let jwksUri = options.jwksUri;
  if (!jwksUri) {
    jwksUri = `${payload.iss}/.well-known/jwks.json`;
  }
  let jwks = options.jwks;
  let jwk = options.jwk;
  try {
    if (jwk || jwks) {
      let jwkOrJwks;
      try {
        jwkOrJwks = JSON.parse(jwk || jwks);
      } catch (err) {
        throw new Error(`Invalid ${jwks ? "JWKS" : "JWK"}: ${err.message}`);
      }
      verifyJwtSync(jwt, jwkOrJwks, {
        issuer: options.issuer ?? null,
        audience: options.audience ?? null,
      });
    } else {
      await verifyJwt(jwt, jwksUri, {
        issuer: options.issuer ?? null,
        audience: options.audience ?? null,
      });
    }
    viewJwt(jwt, options);
    if (!options.json) console.log("TOKEN IS VALID");
  } catch (err) {
    if (!options.json) viewJwt(jwt, options);
    if (!options.json) console.log("TOKEN IS NOT VALID:");
    throw err;
  }
}

function usage() {
  console.log(`aws-jwt-verify <command> <jwt> [options]

Verify (or just view) an RS256 signed JWT.



Options:
  --version                Show version number                                 [boolean]
  -d, --delete             Delete old files from the S3 bucket                 [boolean]
  --cache-control-mapping  Path to custom JSON file that maps glob patterns to
                            cache-control headers                                [string]
  -p, --prefix             Path prefix to prepend to every S3 object key of uploaded
                            files                                                [string]
  --profile                AWS profile to use                                   [string]
  --help                   Show help                                           [boolean]`);
}

function messageFromError(err) {
  return `${err.constructor.name}: ${err.message}`;
}

function exitWithError(err) {
  console.error(messageFromError(err));
  process.exit(1);
}

function getLongestKeyLength(...objects) {
  let longestKeyLength = 0;
  objects.forEach((o) =>
    Object.keys(o).forEach((key) => {
      if (key.length > longestKeyLength) longestKeyLength = key.length;
    })
  );
  return longestKeyLength;
}

function spaces(nrOfSpaces) {
  return [...new Array(nrOfSpaces + 1)].join(" ");
}

function displayKeys(o, longestKeyLength) {
  return Object.entries(o)
    .map(([k, v]) => {
      const nrOfSpaces = longestKeyLength - k.length;
      return `${spaces(nrOfSpaces)}${k}: ${JSON.stringify(v)}`;
    })
    .join("\n");
}

main().catch(exitWithError);
