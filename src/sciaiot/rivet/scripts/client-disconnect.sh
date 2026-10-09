#!/bin/bash

# OpenVPN environment variables are available when this script is run.
# See: https://openvpn.net/community-resources/reference-manual-for-openvpn-2-6/

CLIENT_NAME="$common_name"
REMOTE_ADDRESS="$untrusted_ip:$untrusted_port"
DISCONNECTED_TIME=$(date -Is) # ISO 8601 format, suitable for JSON

# Construct the JSON payload
JSON_PAYLOAD=$(cat <<EOF
{
    "remote_address": "$REMOTE_ADDRESS",
    "disconnected_time": "$DISCONNECTED_TIME"
}
EOF
)

# Send the PUT request using curl
curl -X PUT \
    -H 'Content-Type: application/json' \
    -d "$JSON_PAYLOAD" \
    "http://127.0.0.1:8000/clients/$CLIENT_NAME/connections"

# Optional: Add error handling
if [ $? -ne 0 ]; then
    echo 'Error sending PUT request.' >&2 # Send error to stderr
    exit 1 # Indicate failure
fi

exit 0 # Indicate success
