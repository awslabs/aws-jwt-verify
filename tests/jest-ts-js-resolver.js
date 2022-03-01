/**
 * Custom resolver for jest
 */
const path = require("path");
const srcPath = path.join(__dirname, "..", "src");
module.exports = (request, options) => {
  if (options.basedir.startsWith(srcPath)) {
    if (request.endsWith("#node-web-compat")) {
      // when running unit tests, we want to use the Node.js implementation (not Web)
      request = request.replace(
        "#node-web-compat",
        "./node-web-compat-node.ts"
      );
    } else {
      // needed because of this issue: https://github.com/kulshekhar/ts-jest/issues/1057
      request = request.replace(/\.js$/, ".ts");
    }
  }
  return options.defaultResolver(request, options);
};
