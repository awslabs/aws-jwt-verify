import { defineConfig } from "cypress";
import setupPlugins from "./cypress/plugins";

export default defineConfig({
  e2e: {
    env: {
      CI: process.env.CI,
    },
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
      return setupPlugins(on, config);
    },
    baseUrl: "http://127.0.0.1:5173/",
  },
});
