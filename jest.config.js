module.exports = {
  preset: "ts-jest",
  testEnvironment: "node",
  moduleFileExtensions: ["ts", "js"],
  collectCoverageFrom: ["src/*.ts"],
  roots: ["src", "tests/unit"],
  resolver: "<rootDir>/tests/jest-ts-js-resolver.js",
};
