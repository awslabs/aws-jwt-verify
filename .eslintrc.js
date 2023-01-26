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
    "no-restricted-globals": [
      "error",
      {
        name: "window",
        message:
          "Don't use the window global, as you don't need to use it and it's not a defined global in the Next.js Edge Runtime",
      },
    ],
  },
};
