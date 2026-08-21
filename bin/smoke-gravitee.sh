#!/usr/bin/env bash
# Logs in through Gravitee AM without a browser, and checks what came out of it.
#
# Usage: bin/smoke-gravitee.sh   (needs "make start" to have run)
set -euo pipefail

cd "$(dirname "$0")/.."

APP=http://localhost:8001
CA=docker/certs/ca.crt
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
JAR=$TMP/app.jar
GJAR=$TMP/gravitee.jar

step() { printf '\n=== %s\n' "$1"; }
ok()   { echo "OK: $1"; }
die()  { echo "FAIL: $1"; exit 1; }

step "1. GET /gravitee while anonymous, expect a redirect to the provider"
authz=$(curl -s -o /dev/null -c "$JAR" -b "$JAR" -w '%{redirect_url}' "$APP/gravitee")
echo "$authz" | sed 's/&/\n  &/g'
case "$authz" in
    https://localhost:9443/demo/oauth/authorize*) ok "authorization endpoint, over https" ;;
    *) die "unexpected redirect: $authz" ;;
esac
for param in 'response_type=code' 'client_id=symfony-demo' 'code_challenge=' 'code_challenge_method=S256' 'state=' 'nonce='; do
    case "$authz" in *"$param"*) ok "$param" ;; *) die "missing $param" ;; esac
done

step "2. GET the Gravitee login page"
# the authorization endpoint bounces to /demo/login, and the session cookie set on that
# hop is what the form POST is checked against, so follow it in the same jar
curl -s --cacert "$CA" -c "$GJAR" -b "$GJAR" -L "$authz" -o "$TMP/login.html"
action=$(grep -oE 'action="[^"]*"' "$TMP/login.html" | head -1 | sed 's/^action="//; s/"$//' \
    | python3 -c 'import sys,html; print(html.unescape(sys.stdin.read().strip()))')
xsrf=$(grep -oE 'name="X-XSRF-TOKEN"[^>]*value="[^"]*"' "$TMP/login.html" \
    | grep -oE 'value="[^"]*"' | sed 's/value="//; s/"$//')
[ -n "$action" ] && ok "login form found" || die "no login form"
[ -n "$xsrf" ] && ok "CSRF token found" || die "no X-XSRF-TOKEN on the form"

step "3. POST carol / Gravitee!2026"
# two things this call gets wrong easily: the CSRF token holds "+" characters, which a
# plain -d would send as spaces, hence --data-urlencode; and Gravitee answers with a
# Location header that curl does not always expose as %{redirect_url}, hence -D and grep
location() { grep -i '^location:' "$1" 2>/dev/null | tail -1 | cut -d' ' -f2- | tr -d '\r' || true; }
curl -s -D "$TMP/post.h" --cacert "$CA" -c "$GJAR" -b "$GJAR" -o /dev/null \
    -d "username=carol" --data-urlencode 'password=Gravitee!2026' -d 'client_id=symfony-demo' \
    --data-urlencode "X-XSRF-TOKEN=$xsrf" "$action"
callback=$(location "$TMP/post.h")
case "$callback" in *error_code=*|*error=login_failed*) die "the provider rejected the login: $(echo "$callback" | tr '&' '\n' | grep error_ | tr '\n' ' ')" ;; esac
# Gravitee may insert one hop of its own before handing the code back
for _ in 1 2 3; do
    case "$callback" in "$APP/gravitee/callback"*) break ;; "") die "the provider stopped redirecting" ;; esac
    curl -s -D "$TMP/hop.h" --cacert "$CA" -c "$GJAR" -b "$GJAR" -o /dev/null "$callback"
    callback=$(location "$TMP/hop.h")
done
case "$callback" in
    "$APP/gravitee/callback?"*) ok "sent back to the app callback with a code" ;;
    *) die "unexpected callback: ${callback:-<empty>}" ;;
esac

step "4. GET the callback, where the authenticator runs"
target=$(curl -s -c "$JAR" -b "$JAR" -o /dev/null -w '%{redirect_url}' "$callback")
case "$target" in
    "$APP/gravitee") ok "authenticated, redirected to default_target_path" ;;
    *) die "authentication failed, landed on: ${target:-<nothing>}" ;;
esac

step "5. GET the profile page"
code=$(curl -s -c "$JAR" -b "$JAR" -o "$TMP/profile.html" -w '%{http_code}' "$APP/gravitee")
[ "$code" = 200 ] && ok "the profile page renders 200" || die "http $code"
grep -q 'OidcUser' "$TMP/profile.html" && ok "the user is an OidcUser" || die "no OidcUser on the page"
grep -q 'user_data_source: id_token' "$TMP/profile.html" \
    && ok "the claims came from the ID token, with no UserInfo call" || die "option not shown"

step "6. Log out, expect RP-Initiated Logout at the provider"
logout=$(curl -s -c "$JAR" -b "$JAR" -o /dev/null -w '%{redirect_url}' "$APP/gravitee/logout")
case "$logout" in
    https://localhost:9443/demo/logout*) ok "end_session_endpoint" ;;
    *) die "unexpected logout redirect: ${logout:-<none>}" ;;
esac
case "$logout" in *id_token_hint=*) ok "with an id_token_hint" ;; *) die "no id_token_hint" ;; esac
case "$logout" in *post_logout_redirect_uri=*) ok "with a post_logout_redirect_uri" ;; *) die "no post_logout_redirect_uri" ;; esac

# building the request is not delivering it: the browser is what carries it to the provider,
# so the test has to follow it too or the provider never hears about the logout
curl -s -D "$TMP/end.h" --cacert "$CA" -c "$GJAR" -b "$GJAR" -o /dev/null "$logout"
back=$(location "$TMP/end.h")
case "$back" in
    "$APP/"*) ok "Gravitee sent the browser back to post_logout_redirect_path" ;;
    *) die "unexpected answer from the end session endpoint: ${back:-<none>}" ;;
esac

step "7. The session is gone, the flow starts over"
again=$(curl -s -c "$JAR" -b "$JAR" -o /dev/null -w '%{redirect_url}' "$APP/gravitee")
case "$again" in
    https://localhost:9443/demo/oauth/authorize*) ok "anonymous again" ;;
    *) die "still authenticated: $again" ;;
esac

step "8. The provider forgot the session too, not just Symfony"
# asserting the logout REQUEST is not enough: Turbo Drive once swallowed it entirely, so the
# provider kept its session while every earlier check still passed. What proves it is the
# provider asking for a password again.
fresh=$(curl -s -c "$TMP/fresh.jar" -b "$TMP/fresh.jar" -o /dev/null -w '%{redirect_url}' "$APP/gravitee")
case "$fresh" in
    https://localhost:9443/demo/oauth/authorize*) ok "the app starts a new authorization request" ;;
    *) die "unexpected entry point redirect: ${fresh:-<none>}" ;;
esac
curl -s --cacert "$CA" -c "$GJAR" -b "$GJAR" -L "$fresh" -o "$TMP/reask.html"
if grep -qE 'login-actions/authenticate|name="password"' "$TMP/reask.html"; then
    ok "the provider asks for credentials again, so its own session is gone"
else
    die "the provider signed us straight back in: the end session request had no effect"
fi

printf '\ngravitee: everything checked out.\n'
