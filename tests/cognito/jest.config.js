module.exports = {
  roots: ["<rootDir>/test"],
  testMatch: ["**/*.test.ts"],
  transform: {
    "^.+\\.tsx?$": "ts-jest",
  },
  testEnvironment: "node",
  moduleNameMapper: {
    "#node-web-compat":
      "<rootDir>/node_modules/aws-jwt-verify/dist/cjs/node-web-compat-node.js",
    "aws-jwt-verify/https":
      "<rootDir>/node_modules/aws-jwt-verify/dist/cjs/https.js",
  },
};
