#!/bin/bash -e

run_test() {
    START_SERVER_CMD=$1
    SERVER_PORT=$2
    START_CYPRESS_CMD=$3

    echo "Starting Vite server in background ..."
    $START_SERVER_CMD &
    VITE_PID=$!
    echo "Vite server launched as PID ${VITE_PID}"
    WAITED=0
    while ! nc -z localhost $SERVER_PORT; do
        WAITED=$((WAITED + 1))
        if [ $WAITED -ge 30 ]; then
            echo "Error: Vite server didn't come on-line within $WAITED seconds"
            exit 1
        fi
        echo "Waiting for Vite server to come on-line ($WAITED) ..."
        sleep 1
    done
    if [ ! -z $CI ]; then
        export CYPRESS_VIDEO=false
    fi
    echo "Running cypress tests ..."
    if ! $START_CYPRESS_CMD; then
        echo "Cypress test failed :("
        TEST_FAILED=true
    fi
    if [ -z $CI ]; then
        # Only bother to kill the backgrounded server if we're not running in CI (but e.g. on a developer laptop)
        echo "Sending stop signal to Vite server (PID $VITE_PID) ..."
        kill -INT $VITE_PID
        echo "Waiting for Vite server to actually stop ..."
        wait
        echo "Vite server stopped"
    fi
    if [ ! -z $TEST_FAILED ]; then
        return 1
    fi
}

main() {
    echo "Generating JWTs ..."
    npm run tokengen

    # Run against dev server, which uses esbuild bundler
    echo "Starting Cypress tests against Vite dev server ..."
    run_test "npm run dev" 3000 "npm run cypress:run"

    # Run against preview server too, which uses rollup bundler
    echo "Building Vite app for preview ..."
    npm run build
    echo "Starting Cypress tests against Vite preview server ..."
    run_test "npm run preview" 4173 "npm run cypress:run:preview"
}

main
