#!/bin/bash -e

export NODE_ENV=production

main() {
    # Determine the dir of this script
    DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
    cd $DIR

    # Install aws-jwt-verify
    npm install
    npm remove aws-jwt-verify && npm install --no-save --force --no-package-lock ../../aws-jwt-verify.tgz

    # Compile test files
    npx tsc

    # Generate self-signed certificate to spin up a JWKS server with
    openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/C=US/ST=Oregon/L=Portland/O=Company Name/OU=Org/CN=www.example.com"

    # Run tests
    node test-script.js
}

main
