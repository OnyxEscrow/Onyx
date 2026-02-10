#!/bin/bash

# Source cargo environment
if [ -f ~/.cargo/env ]; then
    source ~/.cargo/env
fi

# Start the server in the background
cargo run --bin server & > /dev/null 2>&1
SERVER_PID=$!

echo "Server started with PID: $SERVER_PID"

# Give the server a few seconds to start up
sleep 5

echo "Testing health check..."
curl http://127.0.0.1:8080/api/health

# Kill the server process
kill $SERVER_PID

echo "Server (PID: $SERVER_PID) stopped."
