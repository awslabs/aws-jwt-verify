import typescriptEslint from "@typescript-eslint/eslint-plugin";
import security from "eslint-plugin-security";
import globals from "globals";
import tsParser from "@typescript-eslint/parser";
import path from "node:path";
import { fileURLToPath } from "node:url";
import js from "@eslint/js";
import { FlatCompat } from "@eslint/eslintrc";
import { includeIgnoreFile } from "@eslint/compat";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const compat = new FlatCompat({
  baseDirectory: __dirname,
  recommendedConfig: js.configs.recommended,
  allConfig: js.configs.all,
});
const gitignorePath = path.resolve(__dirname, ".gitignore");

export default [
  includeIgnoreFile(gitignorePath),
  security.configs.recommended,
  {
    ignores: ["**/*.js", "**/cdk.out"],
  },
  ...compat.extends(
    "eslint:recommended",
    "plugin:@typescript-eslint/recommended"
  ),
  {
    files: ["**/tests/**/*.ts"],
    rules: {
      "@typescript-eslint/no-explicit-any": "off",
      "@typescript-eslint/no-unused-expressions": "off",
    },
  },
  {
    plugins: {
      "@typescript-eslint": typescriptEslint,
      security,
    },

    languageOptions: {
      globals: {
        ...globals.node,
      },

      parser: tsParser,
      ecmaVersion: 12,
      sourceType: "module",
    },

    rules: {
      "linebreak-style": ["error", "unix"],
      "@typescript-eslint/no-non-null-assertion": "off",

      eqeqeq: [
        "error",
        "always",
        {
          null: "ignore",
        },
      ],

      "no-unused-vars": "off",

      "@typescript-eslint/no-unused-vars": [
        "warn",
        {
          argsIgnorePattern: "^_",
          varsIgnorePattern: "^_",
        },
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
  },
];
