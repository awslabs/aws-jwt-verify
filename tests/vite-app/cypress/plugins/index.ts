/// <reference types="cypress" />

import webpackPreprocessor from "@cypress/webpack-preprocessor";
import webpackOptions from "./webpack.config";

const webpackPreprocessorOptions = {
  webpackOptions,
  watchOptions: {},
};

export default (
  on: Cypress.PluginEvents,
  config: Cypress.PluginConfigOptions
) => {
  on("file:preprocessor", webpackPreprocessor(webpackPreprocessorOptions));
  return config;
};
