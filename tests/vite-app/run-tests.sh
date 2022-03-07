#!/bin/bash -e

run_test() {
    START_SERVER_CMD=$1
    SERVER_PORT=$2
    START_CYPRESS_CMD=$3

    echo "Starting Vite server in background ..."
    $START_SERVER_CMD &
    VITE_PID=$!
    echo "Vite server launched as PID ${VITE_PID}"
    while ! nc -z localhost $SERVER_PORT; do
        echo "Waiting for server to come on-line ..."
        sleep 1
    done
    echo "Running cypress tests ..."
    if ! $START_CYPRESS_CMD; then
        echo "Cypress test failed :("
        TEST_FAILED=true
    fi
    echo "Sending stop signal to Vite server (SIGINT) ..."
    kill -s INT $VITE_PID
    echo "Waiting for Vite server to actually stop ..."
    wait
    echo "Vite server stopped"
    if [ ! -z $TEST_FAILED ]; then
        return 1
    fi
}

main() {
    echo "Generating JWTs ..."
    npm run tokengen

    # # Run against dev server, which uses esbuild bundler
    echo "Starting Cypress tests against Vite dev server ..."
    run_test "npm run dev" 3000 "npm run cypress:run"

    # Run against preview server too, which uses rollup bundler
    echo "Building Vite app for preview ..."
    npm run build
    echo "Starting Cypress tests against Vite preview server ..."
    run_test "npm run preview" 4173 "npm run cypress:run:preview"
}

main
