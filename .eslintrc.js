module.exports = {
  env: {
    node: true,
  },
  ignorePatterns: ["*.js", "cdk.out"],
  extends: [
    "eslint:recommended",
    "plugin:@typescript-eslint/recommended",
    "plugin:security/recommended",
  ],
  parser: "@typescript-eslint/parser",
  parserOptions: {
    ecmaVersion: 12,
    sourceType: "module",
  },
  plugins: ["@typescript-eslint", "security"],
  rules: {
    "linebreak-style": ["error", "unix"],
    "@typescript-eslint/no-non-null-assertion": "off",
    eqeqeq: ["error", "always", { null: "ignore" }],
    "no-unused-vars": "off",
    "@typescript-eslint/no-unused-vars": [
      "warn",
      { argsIgnorePattern: "^_", varsIgnorePattern: "^_" },
    ],
  },
};
