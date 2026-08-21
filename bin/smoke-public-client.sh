#!/usr/bin/env bash
# Logs in through Keycloak as a PUBLIC client, one that holds no secret at all, and checks
# that the flow completes. This is the path token_endpoint_auth_method: none takes.
#
# Usage: bin/smoke-public-client.sh   (needs "make start" to have run)
set -euo pipefail

cd "$(dirname "$0")/.."

APP=http://localhost:8001
CA=docker/certs/ca.crt
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
JAR=$TMP/app.jar
KCJAR=$TMP/kc.jar

step() { printf '\n=== %s\n' "$1"; }
ok()   { echo "OK: $1"; }
die()  { echo "FAIL: $1"; exit 1; }

step "1. GET /public while anonymous, expect a redirect to the provider"
authz=$(curl -s -o /dev/null -c "$JAR" -b "$JAR" -w '%{redirect_url}' "$APP/public")
echo "$authz" | sed 's/&/\n  &/g'
case "$authz" in
    https://localhost:8443/realms/demo/protocol/openid-connect/auth*) ok "authorization endpoint, over https" ;;
    *) die "unexpected redirect: $authz" ;;
esac
case "$authz" in *'client_id=symfony-demo-public'*) ok "client_id is the public client" ;; *) die "wrong client_id" ;; esac
# PKCE is not optional for a public client: it is the only thing binding the code to it
for param in 'code_challenge=' 'code_challenge_method=S256' 'state=' 'nonce='; do
    case "$authz" in *"$param"*) ok "$param" ;; *) die "missing $param" ;; esac
done

step "2. GET the Keycloak login page"
curl -s --cacert "$CA" -c "$KCJAR" -b "$KCJAR" "$authz" -o "$TMP/login.html"
action=$(grep -oE 'action="[^"]*login-actions/authenticate[^"]*"' "$TMP/login.html" \
    | head -1 | sed 's/^action="//; s/"$//' \
    | python3 -c 'import sys,html; print(html.unescape(sys.stdin.read().strip()))')
[ -n "$action" ] && ok "login form found" || die "no login form"

step "3. POST alice / password"
callback=$(curl -s --cacert "$CA" -c "$KCJAR" -b "$KCJAR" -o /dev/null -w '%{redirect_url}' \
    -d 'username=alice' -d 'password=password' -d 'credentialId=' "$action")
case "$callback" in
    "$APP/public/callback?"*) ok "sent back to the app callback with a code" ;;
    *) die "unexpected callback: $callback" ;;
esac

step "4. GET the callback: the code is exchanged with NO client secret"
target=$(curl -s -c "$JAR" -b "$JAR" -o /dev/null -w '%{redirect_url}' "$callback")
case "$target" in
    "$APP/public") ok "authenticated, redirected to default_target_path" ;;
    *) die "the exchange failed, landed on: ${target:-<nothing>}" ;;
esac

step "5. GET the profile page"
code=$(curl -s -c "$JAR" -b "$JAR" -o "$TMP/profile.html" -w '%{http_code}' "$APP/public")
[ "$code" = 200 ] && ok "the profile page renders 200" || die "http $code"
grep -q 'OidcUser' "$TMP/profile.html" && ok "the user is an OidcUser" || die "no OidcUser on the page"
grep -q 'token_endpoint_auth_method: none' "$TMP/profile.html" \
    && ok "the page states the client authenticated with no secret" || die "option not shown"

step "6. Log out: RP-Initiated Logout works without a client secret too"
logout=$(curl -s -c "$JAR" -b "$JAR" -o /dev/null -w '%{redirect_url}' "$APP/public/logout")
case "$logout" in
    https://localhost:8443/realms/demo/protocol/openid-connect/logout*) ok "end_session_endpoint" ;;
    *) die "unexpected logout redirect: ${logout:-<none>}" ;;
esac
case "$logout" in *id_token_hint=*) ok "with an id_token_hint, which is what identifies the session" ;; *) die "no id_token_hint" ;; esac
case "$logout" in *post_logout_redirect_uri=*) ok "with a post_logout_redirect_uri" ;; *) die "no post_logout_redirect_uri" ;; esac

step "7. The session is gone, the flow starts over"
again=$(curl -s -c "$JAR" -b "$JAR" -o /dev/null -w '%{redirect_url}' "$APP/public")
case "$again" in
    https://localhost:8443/realms/demo/protocol/openid-connect/auth*) ok "anonymous again" ;;
    *) die "still authenticated: $again" ;;
esac

printf '\npublic client: everything checked out.\n'
