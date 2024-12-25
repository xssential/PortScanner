#!/bin/bash

TARGET_IP="$1"

LOG_FILE="/var/log/p0f/${TARGET_IP}_p0f_output.log"

if [ -z "$TARGET_IP" ]; then
    echo "Usage: $0 <target_ip>"
    exit 1
fi

echo "Received TARGET_IP: $TARGET_IP"

echo "Starting p0f..."
p0f -i eth0 -o "$LOG_FILE" &
P0F_PID=$!

sleep 2

echo "Sending HTTP request to $TARGET_IP..."
curl "$TARGET_IP" > /dev/null 2>&1

sleep 3

echo "Stopping p0f..."
kill $P0F_PID

wait $P0F_PID

echo "p0f stopped."