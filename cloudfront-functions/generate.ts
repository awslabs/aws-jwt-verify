// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Emits a configured copy of jwt-verifier.js, the CloudFront Functions JWT verifier.
//
// Usage (Cognito):
//   npx ts-node cloudfront-functions/generate.ts --user-pool-id us-east-1_abc \
//     --client-id 1example23456789 --token-use access --origin-id jwt-issuer > function.js
// Usage (other OIDC IDP):
//   npx ts-node cloudfront-functions/generate.ts --issuer https://idp.example.com \
//     --jwks-path /.well-known/jwks.json --audience my-api --origin-id jwt-issuer > function.js

import { readFileSync } from "node:fs";
import { join } from "node:path";

/** CloudFront Functions code size limit, in bytes */
export const MAX_FUNCTION_SIZE = 10 * 1024;

export interface CloudFrontFunctionOptions {
  /** Cognito: the User Pool ID. Sets the issuers and the JWKS path. */
  userPoolId?: string;
  /** Cognito: the User Pool's region, if userPoolId is not known yet (e.g. a CDK token) */
  region?: string;
  /** Other IDPs: the issuer, or issuers, of the JWT (iss claim) */
  issuer?: string | string[];
  /** Other IDPs: the path of the JWKS on the issuer's origin, e.g. "/.well-known/jwks.json" */
  jwksPath?: string;
  /** The origin id of the issuer on the distribution. Default "jwt-issuer" */
  jwksOriginId?: string;
  /** Cognito: "id", "access", or null to accept both */
  tokenUse?: "id" | "access" | null;
  /** Cognito: the client id, or ids, the JWT must be for; null to not check */
  clientId?: string | string[] | null;
  /** Other IDPs: the audience, or audiences, the JWT must be for; null to not check */
  audience?: string | string[] | null;
  /** At least one of these scopes must be in the JWT */
  scope?: string | string[] | null;
  /** Cognito: at least one of these groups must be in the JWT */
  groups?: string | string[] | null;
  /** Clock skew to allow on exp and nbf, in seconds. Default 0 */
  graceSeconds?: number;
  /** Prefix of the JWK keys in the KeyValueStore. Default "jwk:" */
  kvsKeyPrefix?: string;
}

const USER_POOL_ID_REGEX = /^(?<region>[a-z]{2}-[a-z]+-\d)_[a-zA-Z0-9]+$/;

/** Syntax that publishes, then fails at run time in cloudfront-js-2.0 */
const UNSUPPORTED_SYNTAX: [RegExp, string][] = [
  [/\?\./, "optional chaining (?.)"],
  [/\.\.\.[A-Za-z_$[{(]/, "spread (...)"],
  [/for\s*\([^)]*\sof\s/, "for...of"],
  [/\(\s*[^()]*\bawait\b/, "await inside call arguments"],
];

/** The Cognito issuers (both formats, as CognitoJwtVerifier accepts) and JWKS path */
export function cognitoIssuer(userPoolId: string, region?: string) {
  if (!region) {
    const match = userPoolId.match(USER_POOL_ID_REGEX);
    if (!match) throw new Error(`Invalid Cognito User Pool ID: ${userPoolId}`);
    region = match.groups!.region;
  }
  return {
    issuers: [
      `https://cognito-idp.${region}.amazonaws.com/${userPoolId}`,
      `https://issuer-cognito-idp.${region}.amazonaws.com/${userPoolId}`,
    ],
    jwksPath: `/${userPoolId}/.well-known/jwks.json`,
    /** Domain name of the origin to add to the distribution */
    originDomainName: `cognito-idp.${region}.amazonaws.com`,
  };
}

function config(options: CloudFrontFunctionOptions) {
  const common = {
    jwksOriginId: options.jwksOriginId ?? "jwt-issuer",
    scope: options.scope ?? null,
    graceSeconds: options.graceSeconds ?? 0,
    kvsKeyPrefix: options.kvsKeyPrefix ?? "jwk:",
  };
  if (options.userPoolId) {
    if (options.tokenUse === undefined || options.clientId === undefined) {
      throw new Error(
        "tokenUse and clientId must be provided or set to null explicitly"
      );
    }
    const { issuers, jwksPath } = cognitoIssuer(
      options.userPoolId,
      options.region
    );
    return {
      verifier: "cognito",
      issuers,
      jwksPath,
      tokenUse: options.tokenUse,
      clientId: options.clientId,
      audience: null,
      groups: options.groups ?? null,
      ...common,
    };
  }
  if (!options.issuer || !options.jwksPath) {
    throw new Error("Provide userPoolId, or issuer and jwksPath");
  }
  if (options.audience === undefined) {
    throw new Error("audience must be provided or set to null explicitly");
  }
  return {
    verifier: "jwt",
    issuers: Array.isArray(options.issuer) ? options.issuer : [options.issuer],
    jwksPath: options.jwksPath,
    tokenUse: null,
    clientId: null,
    audience: options.audience,
    groups: null,
    ...common,
  };
}

/** Checks code for the CloudFront Functions size limit and unsupported syntax */
export function assertDeployable(code: string) {
  const size = Buffer.byteLength(code);
  if (size > MAX_FUNCTION_SIZE) {
    throw new Error(`Function is ${size} bytes, over ${MAX_FUNCTION_SIZE}`);
  }
  for (const [regex, what] of UNSUPPORTED_SYNTAX) {
    const match = code.match(regex);
    if (match) throw new Error(`Unsupported syntax, ${what}: ${match[0]}`);
  }
}

/** Returns the function code for these options, without comments and indentation */
export function generateCloudFrontFunction(
  options: CloudFrontFunctionOptions
): string {
  const template = readFileSync(join(__dirname, "jwt-verifier.js"), "utf8");
  const block = /\/\/ BEGIN CONFIG\n[\s\S]*\/\/ END CONFIG\n/;
  if (!block.test(template)) throw new Error("CONFIG block not found");
  const code = template
    .replace(
      block,
      () => `const CONFIG = ${JSON.stringify(config(options))};\n`
    )
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith("//"))
    .join("\n");
  assertDeployable(code);
  return code + "\n";
}

function parseArgs(argv: string[]): CloudFrontFunctionOptions {
  const args = new Map<string, string>();
  const rest = [...argv];
  while (rest.length) {
    const flag = rest.shift()!;
    const value = rest.shift();
    if (!flag.startsWith("--") || value === undefined) {
      throw new Error(`Bad argument: ${flag}`);
    }
    args.set(flag.slice(2), value);
  }
  const csv = (name: string) => {
    const v = args.get(name);
    return v === undefined ? undefined : v === "null" ? null : v.split(",");
  };
  const tokenUse = args.get("token-use");
  const graceSeconds = args.get("grace-seconds");
  return {
    userPoolId: args.get("user-pool-id"),
    issuer: csv("issuer") ?? undefined,
    jwksPath: args.get("jwks-path"),
    jwksOriginId: args.get("origin-id"),
    tokenUse:
      tokenUse === "null" ? null : (tokenUse as "id" | "access" | undefined),
    clientId: csv("client-id"),
    audience: csv("audience"),
    scope: csv("scope"),
    groups: csv("groups"),
    graceSeconds: graceSeconds === undefined ? undefined : Number(graceSeconds),
    kvsKeyPrefix: args.get("kvs-key-prefix"),
  };
}

if (require.main === module) {
  process.stdout.write(
    generateCloudFrontFunction(parseArgs(process.argv.slice(2)))
  );
}
