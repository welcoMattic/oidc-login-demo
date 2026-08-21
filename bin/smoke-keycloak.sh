#!/usr/bin/env bash
# Logs in through Keycloak without a browser, and checks what came out of it.
#
# Usage: bin/smoke-keycloak.sh   (needs "make start" to have run)
set -euo pipefail

cd "$(dirname "$0")/.."

APP=http://localhost:8001
CA=docker/certs/ca.crt
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
JAR=$TMP/app.jar
KCJAR=$TMP/kc.jar

step() { printf '\n=== %s\n' "$1"; }

step "1. GET /keycloak while anonymous, expect a redirect to the provider"
authz=$(curl -s -o /dev/null -c "$JAR" -b "$JAR" -w '%{redirect_url}' "$APP/keycloak")
echo "$authz" | sed 's/&/\n  &/g'
case "$authz" in
    https://localhost:8443/realms/demo/protocol/openid-connect/auth*) echo "OK: authorization endpoint, over https" ;;
    *) echo "FAIL: unexpected redirect: $authz"; exit 1 ;;
esac
for param in 'response_type=code' 'code_challenge=' 'code_challenge_method=S256' 'state=' 'nonce=' 'scope=openid%20profile%20email'; do
    case "$authz" in *"$param"*) echo "OK: $param" ;; *) echo "FAIL: missing $param"; exit 1 ;; esac
done

step "2. GET the Keycloak login page"
curl -s --cacert "$CA" -c "$KCJAR" -b "$KCJAR" "$authz" -o "$TMP/login.html"
action=$(grep -oE 'action="[^"]*login-actions/authenticate[^"]*"' "$TMP/login.html" \
    | head -1 | sed 's/^action="//; s/"$//' \
    | python3 -c 'import sys,html; print(html.unescape(sys.stdin.read().strip()))')
[ -n "$action" ] && echo "OK: login form found" || { echo "FAIL: no login form"; exit 1; }

step "3. POST alice / password"
callback=$(curl -s --cacert "$CA" -c "$KCJAR" -b "$KCJAR" -o /dev/null -w '%{redirect_url}' \
    -d 'username=alice' -d 'password=password' -d 'credentialId=' "$action")
case "$callback" in
    "$APP/keycloak/callback?"*) echo "OK: sent back to the app callback with a code" ;;
    *) echo "FAIL: unexpected callback: $callback"; exit 1 ;;
esac

step "4. GET the callback, where the authenticator runs"
target=$(curl -s -c "$JAR" -b "$JAR" -o "$TMP/cb.html" -w '%{redirect_url}' "$callback")
[ "$target" = "$APP/keycloak" ] \
    && echo "OK: authenticated, redirected to default_target_path" \
    || { echo "FAIL: got '$target'"; head -30 "$TMP/cb.html"; exit 1; }

step "5. GET the profile page"
code=$(curl -s -c "$JAR" -b "$JAR" -o "$TMP/profile.html" -w '%{http_code}' "$APP/keycloak")
[ "$code" = "200" ] || { echo "FAIL: http $code"; exit 1; }
python3 - "$TMP/profile.html" <<'PY'
import html as htmlmod, re, sys
page = htmlmod.unescape(open(sys.argv[1]).read())
text = re.sub(r'\s+', ' ', re.sub(r'<[^>]+>', ' ', page))
checks = {
    'the identity is the email claim, not sub': 'User identifier alice@keycloak.demo',
    'roles are ROLE_USER, no claim granted any': 'Roles ROLE_USER',
    'the user is an OidcUser': 'Symfony\\Component\\Security\\Core\\User\\OidcUser',
    'the access token is kept on the security token': 'received and kept on the security token',
    'the profile scope brought the name claim': 'Alice Keycloak',
    'the email scope brought the email claim': 'alice@keycloak.demo',
    'the ID token claims are displayed': '"nonce"',
}
failed = [label for label, needle in checks.items() if needle not in text and needle not in page]
for label in checks:
    print(('FAIL: ' if label in failed else 'OK: ') + label)
sys.exit(1 if failed else 0)
PY

step "6. Log out, expect RP-Initiated Logout at the provider"
logout=$(curl -s -c "$JAR" -b "$JAR" -o /dev/null -w '%{redirect_url}' "$APP/keycloak/logout")
case "$logout" in
    https://localhost:8443/realms/demo/protocol/openid-connect/logout*id_token_hint=*post_logout_redirect_uri=*)
        echo "OK: end_session_endpoint, with an id_token_hint and a post_logout_redirect_uri" ;;
    *) echo "FAIL: not an RP-initiated logout: $logout"; exit 1 ;;
esac

step "7. Follow the provider logout"
back=$(curl -s --cacert "$CA" -c "$KCJAR" -b "$KCJAR" -o /dev/null -w '%{redirect_url}' "$logout")
[ "$back" = "$APP/" ] \
    && echo "OK: Keycloak sent the browser back to post_logout_redirect_path" \
    || echo "NOTE: the provider did not redirect back, it answered '$back'"

step "8. The session is gone, the flow starts over"
again=$(curl -s -o /dev/null -c "$JAR" -b "$JAR" -w '%{redirect_url}' "$APP/keycloak")
case "$again" in
    https://localhost:8443/*) echo "OK: anonymous again" ;;
    *) echo "FAIL: still authenticated, got '$again'"; exit 1 ;;
esac

step "9. The provider forgot the session too, not just Symfony"
# asserting the logout REQUEST is not enough: Turbo Drive once swallowed it whole, so the
# provider kept its session while every earlier check still passed. What proves it is the
# provider asking for a password again.
fresh=$(curl -s -c "$TMP/fresh.jar" -b "$TMP/fresh.jar" -o /dev/null -w '%{redirect_url}' "$APP/keycloak")
case "$fresh" in
    https://localhost:8443/realms/demo/protocol/openid-connect/auth*) echo "OK: the app starts a new authorization request" ;;
    *) { echo "FAIL: unexpected entry point redirect: ${fresh:-<none>}"; exit 1; } ;;
esac
curl -s --cacert "$CA" -c "$KCJAR" -b "$KCJAR" -L "$fresh" -o "$TMP/reask.html"
if grep -qE 'login-actions/authenticate|name="password"' "$TMP/reask.html"; then
    echo "OK: the provider asks for credentials again, so its own session is gone"
else
    { echo "FAIL: the provider signed us straight back in: the end session request had no effect"; exit 1; }
fi

printf '\nKeycloak: everything checked out.\n'
