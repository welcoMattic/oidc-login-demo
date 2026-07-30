#!/usr/bin/env bash
# Sets the demo user's password in Authentik. The blueprint creates the user, the
# provider and the application, but a password cannot be expressed in a blueprint.
#
# Usage: docker/authentik/provision.sh [base_url] [token]
set -euo pipefail

BASE="${1:-http://localhost:9000}"
TOKEN="${2:-demo-bootstrap-token}"
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

echo "OIDC discovery:"
curl -s "$BASE/application/o/symfony-demo/.well-known/openid-configuration" \
    | php -r '$d=json_decode(stream_get_contents(STDIN),true); foreach(["issuer","authorization_endpoint","token_endpoint","userinfo_endpoint"] as $k) { echo "  $k: ".($d[$k] ?? "-")."\n"; }'
