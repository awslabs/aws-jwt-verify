# Tests with Vite and Cypress

This is a Vite project allowing browser-based testing using Cypress.

## How to run the tests

- Clone the repo: `git clone https://github.com/awslabs/aws-jwt-verify`
- Install dev dependencies and create installable dist: `cd aws-jwt-verify && npm install && npm run dist`
- Install Vite and Cypress dependencies: `cd tests/vite-app && npm install`
- Start the Vite dev server: `npm run dev`
- Run the Cypress tests: `npm run cypress:open`

To test the Vite distribution build:

- Start the Vite preview server: `npm run preview`
- Run the Cypress tests: `npm run cypress:open:preview`

The tokens used in the test were generated using `npm run tokengen`
