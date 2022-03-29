module.exports = {
  preset: "ts-jest",
  testEnvironment: "node",
  moduleFileExtensions: ["ts", "js"],
  collectCoverageFrom: ["src/*.ts", "!src/node-web-compat-web.ts"],
  roots: ["src", "tests/unit"],
  resolver: "<rootDir>/tests/jest-ts-js-resolver.js",
};
