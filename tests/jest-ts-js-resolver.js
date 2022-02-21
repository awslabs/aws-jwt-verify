/**
 * Custom resolver for jest, needed because of this issue: https://github.com/kulshekhar/ts-jest/issues/1057
 */
const path = require("path");
const srcPath = path.join(__dirname, "..", "src");
module.exports = (request, options) => {
  if (options.basedir.startsWith(srcPath)) {
    if (request.endsWith("node-web-compat.js")) {
      request = request.replace(/\.js$/, ".cjs");
    } else {
      request = request.replace(/\.js$/, ".ts");
    }
  }
  return options.defaultResolver(request, options);
};
