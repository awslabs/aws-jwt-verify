import { defineConfig } from "cypress";

export default defineConfig({
  e2e: {
    env: {
      CI: process.env.CI,
    },
    // We've imported your old cypress plugins here.
    // You may want to clean this up later by importing these.
    setupNodeEvents(on, config) {
      // https://docs.cypress.io/api/node-events/browser-launch-api
      on("before:browser:launch", (browser, launchOptions) => {
        if (browser.family === "chromium" && browser.name !== "electron") {
          // https://developer.mozilla.org/en-US/docs/Web/API/EcdsaParams
          // From version 113: Ed25519 algorithm is behind the #enable-experimental-web-platform-features preference
          launchOptions.args.push(
            "--enable-experimental-web-platform-features"
          );

          return launchOptions;
        }
      });
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      return require("./cypress/plugins/index.js")(on, config);
    },
    baseUrl: "http://127.0.0.1:5173/",
  },
});
