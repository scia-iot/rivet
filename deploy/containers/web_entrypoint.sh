#!/bin/sh
# Render only validated public settings into the container's private tmpfs.
set -eu
export LC_ALL=C
umask 077

invalid_config() {
    printf '%s\n' 'Invalid public Entra configuration; set valid OVPNCP_UI_ENTRA_TENANT_ID, OVPNCP_UI_ENTRA_CLIENT_ID and OVPNCP_UI_ENTRA_API_SCOPE.' >&2
    exit 1
}

validate_uuid() {
    case "$1" in
        ''|*[!0-9a-fA-F-]*) invalid_config ;;
    esac
    [ "${#1}" -eq 36 ] || invalid_config
    printf '%s\n' "$1" | grep -Eq '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$' || invalid_config
}

tenant_id=${OVPNCP_UI_ENTRA_TENANT_ID:-}
client_id=${OVPNCP_UI_ENTRA_CLIENT_ID:-}
api_scope=${OVPNCP_UI_ENTRA_API_SCOPE:-}
validate_uuid "$tenant_id"
validate_uuid "$client_id"
case "$api_scope" in
    ''|*[!a-zA-Z0-9.:_~/-]*) invalid_config ;;
esac
[ "${#api_scope}" -le 2048 ] || invalid_config
printf '%s\n' "$api_scope" | grep -Eq '^(api|https)://[A-Za-z0-9][A-Za-z0-9.-]*/[A-Za-z0-9._~/-]+$' || invalid_config

print_config() {
    # Validation excludes quotes, escapes, markup, whitespace and script syntax.
    printf 'window.__OVPNCP_CONFIG__ = {"tenantId":"%s","clientId":"%s","apiScope":"%s"};\n' "$tenant_id" "$client_id" "$api_scope"
}

if [ "${1:-}" = '--print-config' ]; then
    print_config
    exit 0
fi

config_tmp=$(mktemp /tmp/ovpncp-runtime-config.XXXXXX)
trap 'rm -f -- "$config_tmp"' EXIT HUP INT TERM
print_config > "$config_tmp"
mv -fT -- "$config_tmp" /tmp/ovpncp-runtime-config.js
trap - EXIT HUP INT TERM
exec "$@"
