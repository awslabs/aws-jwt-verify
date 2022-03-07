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

    echo "Building Vite app for preview ..."
    npm run build
    echo "Starting Vite preview server in background ..."
    npm run preview &
    VITE_PID=$!
    echo "Vite preview server launched as PID ${VITE_PID}"
    while ! nc -z localhost 4173; do
        echo "Waiting for preview server to come on-line ..."
        sleep 1
    done
    echo "Running cypress tests ..."
    if ! npm run cypress:run:preview; then
        echo "Cypress test failed :("
        TEST_FAILED=true
    fi
    echo "Sending stop signal to Vite preview server (SIGINT) ..."
    kill -s INT $VITE_PID
    echo "Waiting for Vite preview server to actually stop ..."
    wait
    echo "Vite preview server stopped"
    if [ ! -z $TEST_FAILED ]; then
        return 1
    fi
}

main
