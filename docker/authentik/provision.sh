#!/usr/bin/env bash
# Finishes the authentik provisioning: the blueprint creates the user, the provider and
# the application, but it cannot set a password, and the stock authentication flow needs
# one binding removed. Run by "make start"; idempotent, so re-running it is harmless.
#
# Usage: docker/authentik/provision.sh [api_url] [token]
#
# The API is reached over plain HTTP on the port compose publishes for it (9000 on the
# host is commonly taken by php-fpm). The app itself never uses that port: it goes
# through the HTTPS front on 9443, which is where the announced issuer comes from.
set -euo pipefail

cd "$(dirname "$0")/../.."

BASE="${1:-http://localhost:9100}"
TOKEN="${2:-demo-bootstrap-token}"
ISSUER="https://localhost:9443/application/o/symfony-demo/"
USERNAME="bob"
PASSWORD="password"

auth=(-H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json")

echo "waiting for authentik API..."
for i in $(seq 1 60); do
    if curl -sf "${auth[@]}" "$BASE/api/v3/root/config/" >/dev/null 2>&1; then
        echo "authentik API is up"
        break
    fi
    sleep 5
done

echo "waiting for the blueprint to create user '$USERNAME'..."
uid=""
for i in $(seq 1 40); do
    uid=$(curl -s "${auth[@]}" "$BASE/api/v3/core/users/?username=$USERNAME" 2>/dev/null \
        | php -r '$d=json_decode(stream_get_contents(STDIN),true); echo $d["results"][0]["pk"] ?? "";' 2>/dev/null)
    [ -n "$uid" ] && break
    sleep 5
done

if [ -z "$uid" ]; then
    echo "ERROR: user '$USERNAME' was not created by the blueprint" >&2
    exit 1
fi
echo "user '$USERNAME' has pk=$uid"

curl -sf "${auth[@]}" -X POST "$BASE/api/v3/core/users/$uid/set_password/" \
    -d "{\"password\":\"$PASSWORD\"}" >/dev/null
echo "password set for '$USERNAME'"

# The stock default-authentication-flow binds an MFA validation stage, which stalls a
# password-only demo login. Drop that binding so the flow is identification -> password.
echo "removing the MFA validation stage from default-authentication-flow..."
fpk=$(curl -s "${auth[@]}" "$BASE/api/v3/flows/instances/?slug=default-authentication-flow" \
    | php -r '$d=json_decode(stream_get_contents(STDIN),true); echo $d["results"][0]["pk"] ?? "";')
if [ -n "$fpk" ]; then
    curl -s "${auth[@]}" "$BASE/api/v3/flows/bindings/?target=$fpk" \
        | php -r '$d=json_decode(stream_get_contents(STDIN),true);
                  foreach (($d["results"] ?? []) as $b) {
                      if (str_contains($b["stage_obj"]["component"] ?? "", "authenticator-validate")) { echo $b["pk"]."\n"; }
                  }' \
        | while read -r bpk; do
            [ -n "$bpk" ] && curl -s "${auth[@]}" -X DELETE "$BASE/api/v3/flows/bindings/$bpk/" >/dev/null \
                && echo "  removed binding $bpk"
        done
fi

echo "OIDC discovery, as the app sees it (through the HTTPS front):"
curl -sf --cacert docker/certs/ca.crt "${ISSUER}.well-known/openid-configuration" \
    | php -r '$d=json_decode(stream_get_contents(STDIN),true); foreach(["issuer","authorization_endpoint","token_endpoint","userinfo_endpoint","end_session_endpoint"] as $k) { echo "  $k: ".($d[$k] ?? "-")."\n"; }' \
    || echo "  WARNING: $ISSUER did not answer; is the authentik_tls container up?"
