#!/bin/bash -e

main() {
    echo "Generating JWTs ..."
    npm run tokengen

    echo "Starting Vite dev server in background ..."
    npm run dev &
    VITE_PID=$!
    echo "Vite dev server launched as PID ${VITE_PID}"
    while ! nc -z localhost 3000; do
        echo "Waiting for dev server to come on-line ..."
        sleep 1
    done
    echo "Running cypress tests ..."
    if ! npm run cypress:run; then
        echo "Cypress test failed :("
        TEST_FAILED=true
    fi
    echo "Sending stop signal to Vite dev server (SIGINT) ..."
    kill -s INT $VITE_PID
    echo "Waiting for Vite dev server to actually stop ..."
    wait
    echo "Vite dev server stopped"
    if [ ! -z $TEST_FAILED ]; then
        return 1
    fi
}

main
