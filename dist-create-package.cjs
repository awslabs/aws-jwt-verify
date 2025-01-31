/* eslint @typescript-eslint/no-require-imports: "off" */
const pkg = require("./package.json");
const fs = require("fs");
const path = require("path");

const targetType = process.argv[2];

if (!["cjs", "esm"].includes(targetType)) {
  throw new Error("Specify cjs or esm");
}

const { name, version } = pkg;

// eslint-disable-next-line security/detect-non-literal-fs-filename
fs.writeFileSync(
  path.join(__dirname, "dist", targetType, "package.json"),
  JSON.stringify({
    name,
    version,
    type: targetType === "cjs" ? "commonjs" : "module",
    imports: {
      "#node-web-compat": {
        browser: "./node-web-compat-web.js",
        default: "./node-web-compat-node.js",
      },
    },
  })
);
