module.exports = {
  roots: ["<rootDir>/test"],
  testMatch: ["**/*.test.ts"],
  transform: {
    "^.+\\.tsx?$": "ts-jest",
  },
  testEnvironment: "node",
  moduleNameMapper: {
    "aws-jwt-verify/https":
      "<rootDir>/node_modules/aws-jwt-verify/dist/cjs/https.js", // Jest, why do we need this ... :|
  },
};
