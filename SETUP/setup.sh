#!/bin/bash

SCRIPT_DIR=$(dirname "$(readlink -f "$0")")

OS_DIR="$SCRIPT_DIR/../OS"

if [ "$1" == "install" ]; then
    cd "$OS_DIR" || { echo "OS directory not found"; exit 1; }
    docker build -t p0f .
    echo "Docker image 'p0f' built successfully."
elif [ "$1" == "remove" ]; then
    docker rmi -f p0f
    echo "Docker image 'p0f' removed successfully."
else
    echo "Usage: $0 {install|remove}"
fi