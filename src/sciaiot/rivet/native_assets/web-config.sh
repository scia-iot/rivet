#!/bin/sh
# Render validated public Entra settings for the static browser build.
set -eu
export LC_ALL=C

invalid_config() {
    printf '%s\n' 'Invalid public Entra configuration.' >&2
    exit 1
}

validate_uuid() {
    case "$1" in
        ''|*[!0-9a-fA-F-]*) invalid_config ;;
    esac
    [ "${#1}" -eq 36 ] || invalid_config
    printf '%s\n' "$1" | grep -Eq '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$' || invalid_config
}

tenant_id=${RIVET_UI_ENTRA_TENANT_ID:-}
client_id=${RIVET_UI_ENTRA_CLIENT_ID:-}
api_scope=${RIVET_UI_ENTRA_API_SCOPE:-}
provider=${RIVET_UI_AUTH_PROVIDER-entra}
[ "$provider" = 'entra' ] || invalid_config
validate_uuid "$tenant_id"
validate_uuid "$client_id"
case "$api_scope" in
    ''|*[!a-zA-Z0-9.:_~/-]*) invalid_config ;;
esac
[ "${#api_scope}" -le 2048 ] || invalid_config
printf '%s\n' "$api_scope" | grep -Eq '^(api|https)://[A-Za-z0-9][A-Za-z0-9.-]*/[A-Za-z0-9._~/-]+$' || invalid_config

printf 'window.__RIVET_CONFIG__ = {"provider":"entra","tenantId":"%s","clientId":"%s","apiScope":"%s"};\n' "$tenant_id" "$client_id" "$api_scope"
