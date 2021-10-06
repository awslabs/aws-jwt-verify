#!/usr/bin/env ts-node

import * as fs from "fs";
import * as path from "path";

/**
 * Create a subfolder with a package.json file
 * for each submodule of aws-jwt-verify, thereby making it possible to import
 * submodules like this (using "/") in TypeScript:
 *
 * import * as jwk from "aws-jwt-verify/jwk";
 *
 * This is needed in addition to specifying exports in package.json
 * until TypeScript implements: https://github.com/microsoft/TypeScript/issues/33079
 */

// eslint-disable-next-line @typescript-eslint/no-var-requires
const packageExports = require("./package.json").exports as {
  [exportName: string]: unknown;
};
const submodules = Object.keys(packageExports)
  .filter((exportName) => exportName !== ".")
  .map((exportName) => exportName.replace("./", ""));

for (const submodule of submodules) {
  // eslint-disable-next-line security/detect-non-literal-fs-filename
  fs.mkdirSync(submodule, { recursive: true });
  // eslint-disable-next-line security/detect-non-literal-fs-filename
  fs.writeFileSync(
    path.join(__dirname, submodule, "package.json"),
    JSON.stringify(
      {
        main: `../dist/cjs/${submodule}.js`,
        module: `../dist/esm/${submodule}.js`,
        types: `../dist/esm/${submodule}.d.ts`,
      },
      null,
      2
    )
  );
}
