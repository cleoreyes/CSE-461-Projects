#!/bin/bash

# Get directory where this script is located
dname=$(dirname "${BASH_SOURCE[0]}")

# Run the server script with server_name and port
python3 "$dname/server.py" "$1" "$2"
