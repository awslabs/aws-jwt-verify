# Usage in the Web Browser

`tests\vite-app` is a Vite project demonstrating browser usage of `aws-jwt-verify`
including how to configure browser-based testing using Cypress.

## Vite

The [Why Vite](https://vitejs.dev/guide/why.html) page highlight how code is bundled differently for dev vs. production:

- Vite pre-bundles dependencies using esbuild.
- Vite serves source code over native ESM.
- Vite bundles for production using Rollup.

When using Rollup, `aws-jwt-verify` requires `@rollup/plugin-node-resolve` and the `{ browser: true }` configuration.
Here is the minimal `vite.config.js` to support that:

```javascript
import { defineConfig } from "vite";
import resolve from "@rollup/plugin-node-resolve";

export default defineConfig({
  build: {
    rollupOptions: {
      plugins: [resolve({ browser: true })],
    },
  },
});
```

## Cypress

The `cypress\integration` folder includes both functional tests that interact
with an HTML form in the web browser and unit tests that use `JwtRsaVerifier`
directly. To enable the unit tests to work, `@cypress/webpack-preprocessor` is
required. Here is the minimal `cypress\plugins\index.js` to support that:

```javascript
const webpackPreprocessor = require("@cypress/webpack-preprocessor");

module.exports = (on, config) => {
  const options = webpackPreprocessor.defaultOptions;
  on("file:preprocessor", webpackPreprocessor(options));

  // additional code including vite "dev-server:start"
  return config;
};
```

## How to run the tests

If you haven't already done so, create a local build of `aws-jwt-verify`:

- Clone the repo: `git clone https://github.com/awslabs/aws-jwt-verify`
- Install dev dependencies and create installable archive: `cd aws-jwt-verify && npm install && npm run pack-for-tests`
- Install Vite and Cypress dependencies: `cd tests/vite-app && npm install`

The `run-tests.sh` script will test browser usage by:

1. Generating JWTs and a JWKS for the tests (`npm run tokengen`).

2. Starting the Vite dev server (`npm run dev`) and running the Cypress tests (`npm run cypress:run`).

3. Running a Vite distribution build (`npm run build`), starting the Vite preview server (`npm run preview`), and running the Cypress tests (`npm run cypress:run:preview`)

## Summary

The combination of running both functional and unit tests, against both the Vite dev and preview server
has the result of providing samples for and testing `aws-jwt-verify` with each of webpack, Rollup, and native ESM.
