#!/usr/bin/env bash
# Browserless login through ONE scenario using curl and python3 for HTML unescaping.
#
# Usage: bin/smoke.sh <firewall> [--authz <substring>]... [--login-page <substring>]... [--page <substring>]...
#
# Steps (each prints OK/FAIL and exits 1 on failure):
#   (1) GET /<firewall>/start with a cookie jar, expect 302 to Keycloak with response_type=code, state=, nonce=, scope=openid
#   (2) GET the Keycloak auth URL, find the login form action (login-actions/authenticate) and unescape it, check --login-page substrings
#   (3) POST username=alice, password=alice to the form action, expect 302 to /<firewall>/callback
#   (4) GET the callback with the app jar, expect 302 to /<firewall>/account
#   (5) GET the account page, expect 200 and --page substrings in the HTML-unescaped, tag-stripped text
#   (6) GET /<firewall>/logout, expect 302 to Keycloak end_session_endpoint with id_token_hint and post_logout_redirect_uri
#   (7) Follow the logout redirect, then GET the auth URL with the KC_JAR and assert login form is shown again (provider session is gone)

set -euo pipefail

cd "$(dirname "$0")/.."

# Parse arguments
FIREWALL=""
AUTHZ_SUBSTRINGS=()
LOGIN_PAGE_SUBSTRINGS=()
PAGE_SUBSTRINGS=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --authz)
            shift
            AUTHZ_SUBSTRINGS+=("$1")
            ;;
        --login-page)
            shift
            LOGIN_PAGE_SUBSTRINGS+=("$1")
            ;;
        --page)
            shift
            PAGE_SUBSTRINGS+=("$1")
            ;;
        *)
            if [[ -z "$FIREWALL" ]]; then
                FIREWALL="$1"
            else
                echo "ERROR: Unknown option or multiple firewalls: $1"
                exit 1
            fi
            ;;
    esac
    shift
done

if [[ -z "$FIREWALL" ]]; then
    echo "ERROR: No firewall specified"
    echo "Usage: $0 <firewall> [--authz <substring>]... [--login-page <substring>]... [--page <substring>]..."
    exit 1
fi

# File paths
APP_JAR="$(mktemp)"
KC_JAR="$(mktemp)"
FRESH_APP_JAR="$(mktemp)"

# Cleanup
trap "rm -f '$APP_JAR' '$KC_JAR' '$FRESH_APP_JAR'" EXIT

# curl answered nothing: the server dropped the connection, which set -e would otherwise turn into a silent exit
require_status() {
    if [[ -z "$1" ]]; then
        echo "FAIL: no HTTP status, the request got no answer (${2:-unknown request})"
        exit 1
    fi
}

echo "Testing firewall: $FIREWALL"

# Helper function to check if a string contains all required substrings (literal match)
check_substrings() {
    local content="$1"
    shift
    local substrings=("$@")
    local count=${#substrings[@]}
    
    if [[ $count -eq 0 ]]; then
        return 0
    fi
    
    local i=0
    while [[ $i -lt $count ]]; do
        local substr="${substrings[$i]}"
        if [[ -z "$substr" ]]; then
            i=$((i + 1))
            continue
        fi
        if [[ "$content" != *"$substr"* ]]; then
            echo "FAIL: Missing substring: $substr"
            return 1
        fi
        i=$((i + 1))
    done
    
    return 0
}

# Helper function to unescape HTML entities
unescape_html() {
    local html="$1"
    python3 -c "
import html
import sys
content = sys.stdin.read()
print(html.unescape(content), end='')
" <<< "$html"
}

# Helper function to unescape HTML and strip tags for text comparison
unescape_and_strip() {
    local html="$1"
    python3 -c "
import html
import re
import sys
content = sys.stdin.read()
# Unescape HTML entities
content = html.unescape(content)
# Strip HTML tags
content = re.sub(r'<[^>]*>', ' ', content)
# Normalize whitespace
content = re.sub(r'\s+', ' ', content).strip()
print(content)
" <<< "$html"
}

# (1) GET /<firewall>/start with app cookie jar, expect 302 to Keycloak
START_URL="http://localhost:8001/${FIREWALL}/start"
echo -n "(1) GET $START_URL with app jar... "

response=$(curl -s -i -c "$APP_JAR" -b "$APP_JAR" "$START_URL" 2>/dev/null || true)
http_code=$(printf '%s\n' "${response%%$'\n'*}" | grep -oE '[0-9]{3}' | head -1 || true)
require_status "$http_code" "step at line 137"
location=$(echo "$response" | grep -iE '^Location:' | sed 's/Location: //i' | tr -d '\r' || true)

echo "HTTP $http_code, Location: $location"

if [[ "$http_code" != "302" ]]; then
    echo "FAIL: Expected 302, got $http_code"
    exit 1
fi

if ! echo "$location" | grep -qF -- "https://localhost:8443/realms/demo/protocol/openid-connect/auth"; then
    echo "FAIL: Location does not start with Keycloak auth endpoint"
    exit 1
fi

# Check required authz parameters
echo -n "    Checking authz parameters... "
if ! echo "$location" | grep -qF -- "response_type=code"; then
    echo "FAIL: Missing response_type=code"
    exit 1
fi

if ! echo "$location" | grep -qF -- "state="; then
    echo "FAIL: Missing state parameter"
    exit 1
fi

if ! echo "$location" | grep -qF -- "nonce="; then
    echo "FAIL: Missing nonce parameter"
    exit 1
fi

if ! echo "$location" | grep -qF -- "scope=openid"; then
    echo "FAIL: Missing scope=openid"
    exit 1
fi

# Check custom authz parameters from arguments
if [[ ${#AUTHZ_SUBSTRINGS[@]} -gt 0 ]]; then
    if ! check_substrings "$location" "${AUTHZ_SUBSTRINGS[@]}"; then
        exit 1
    fi
fi

echo "OK"

# (2) GET the auth URL with Keycloak jar, find login form and check login page substrings
AUTH_URL="$location"
echo -n "(2) GET $AUTH_URL with Keycloak jar... "

response=$(curl -s -i -c "$KC_JAR" -b "$KC_JAR" "$AUTH_URL" 2>/dev/null || true)
http_code=$(printf '%s\n' "${response%%$'\n'*}" | grep -oE '[0-9]{3}' | head -1 || true)
require_status "$http_code" "step at line 188"

echo "HTTP $http_code"

if [[ "$http_code" != "200" ]]; then
    echo "FAIL: Expected 200, got $http_code"
    exit 1
fi

# Find the login form action specifically (the one containing login-actions/authenticate)
# Extract the action attribute and unescape it
form_action=$(echo "$response" | grep -oE 'action="[^"]*login-actions/authenticate[^"]*"' | head -1 | sed 's/action="//;s/"$//' || true)
if [[ -z "$form_action" ]]; then
    echo "FAIL: No login form with login-actions/authenticate found"
    exit 1
fi

# Unescape HTML entities in the form action
form_action=$(unescape_html "$form_action")

# Make it absolute
if ! echo "$form_action" | grep -qF -- "https://"; then
    # Relative to the auth URL
    base_url=$(echo "$AUTH_URL" | sed 's|/protocol/openid-connect/auth.*||')
    form_action="${base_url}${form_action}"
fi

echo "    Form action: $form_action"

# Check login page content for required substrings
if [[ ${#LOGIN_PAGE_SUBSTRINGS[@]} -gt 0 ]]; then
    form_html=$(echo "$response" | sed '1,/^$/d')  # Remove headers
    if ! check_substrings "$form_html" "${LOGIN_PAGE_SUBSTRINGS[@]}"; then
        exit 1
    fi
fi

echo "OK"

# (3) POST username=alice, password=alice to form action, expect 302 to callback
CSRF_TOKEN=$(echo "$response" | grep -oE 'name="[^"]*" value="[^"]*"' | grep -i csrf || true)
if [[ -n "$CSRF_TOKEN" ]]; then
    # Extract csrf token name and value
    csrf_name=$(echo "$CSRF_TOKEN" | grep -oE 'name="[^"]*"' | sed 's/name="//;s/"$//')
    csrf_value=$(echo "$CSRF_TOKEN" | grep -oE 'value="[^"]*"' | sed 's/value="//;s/"$//')
    POST_DATA="${csrf_name}=${csrf_value}&username=alice&password=alice&credentialId="
else
    POST_DATA="username=alice&password=alice&credentialId="
fi

echo -n "(3) POST login form... "

response=$(curl -s -i -c "$KC_JAR" -b "$KC_JAR" -X POST -d "$POST_DATA" "$form_action" 2>/dev/null || true)
http_code=$(printf '%s\n' "${response%%$'\n'*}" | grep -oE '[0-9]{3}' | head -1 || true)
require_status "$http_code" "step at line 241"
location=$(echo "$response" | grep -iE '^Location:' | sed 's/Location: //i' | tr -d '\r' || true)

echo "HTTP $http_code, Location: $location"

if [[ "$http_code" != "302" ]]; then
    echo "FAIL: Expected 302, got $http_code"
    exit 1
fi

EXPECTED_CALLBACK="http://localhost:8001/${FIREWALL}/callback"
if ! echo "$location" | grep -qF -- "${EXPECTED_CALLBACK}?"; then
    echo "FAIL: Expected redirect to ${EXPECTED_CALLBACK}, got $location"
    exit 1
fi

echo "OK"

# (4) GET the callback with app jar, expect 302 to account page
CALLBACK_URL="$location"
echo -n "(4) GET $CALLBACK_URL with app jar... "

response=$(curl -s -i -c "$APP_JAR" -b "$APP_JAR" "$CALLBACK_URL" 2>/dev/null || true)
http_code=$(printf '%s\n' "${response%%$'\n'*}" | grep -oE '[0-9]{3}' | head -1 || true)
require_status "$http_code" "step at line 264"
location=$(echo "$response" | grep -iE '^Location:' | sed 's/Location: //i' | tr -d '\r' || true)

echo "HTTP $http_code, Location: $location"

if [[ "$http_code" != "302" ]]; then
    echo "FAIL: Expected 302, got $http_code"
    exit 1
fi

EXPECTED_ACCOUNT="http://localhost:8001/${FIREWALL}/account"
if [[ "$location" != "$EXPECTED_ACCOUNT" ]]; then
    echo "FAIL: Expected redirect to $EXPECTED_ACCOUNT, got $location"
    exit 1
fi

echo "OK"

# (5) GET the account page, expect 200 and page content substrings
ACCOUNT_URL="$location"
echo -n "(5) GET $ACCOUNT_URL... "

response=$(curl -s -i -c "$APP_JAR" -b "$APP_JAR" "$ACCOUNT_URL" 2>/dev/null || true)
http_code=$(printf '%s\n' "${response%%$'\n'*}" | grep -oE '[0-9]{3}' | head -1 || true)
require_status "$http_code" "step at line 287"
body=$(echo "$response" | sed '1,/^$/d')  # Remove headers

echo "HTTP $http_code"

if [[ "$http_code" != "200" ]]; then
    echo "FAIL: Expected 200, got $http_code"
    exit 1
fi

# Check page content substrings in the text (unescaped and tag-stripped)
if [[ ${#PAGE_SUBSTRINGS[@]} -gt 0 ]]; then
    page_text=$(unescape_and_strip "$body")
    if ! check_substrings "$page_text" "${PAGE_SUBSTRINGS[@]}"; then
        exit 1
    fi
fi

echo "OK"

# (6) GET logout, expect 302 to Keycloak end_session_endpoint with id_token_hint and post_logout_redirect_uri
LOGOUT_URL="http://localhost:8001/${FIREWALL}/logout"
echo -n "(6) GET $LOGOUT_URL... "

response=$(curl -s -i -c "$APP_JAR" -b "$APP_JAR" "$LOGOUT_URL" 2>/dev/null || true)
http_code=$(printf '%s\n' "${response%%$'\n'*}" | grep -oE '[0-9]{3}' | head -1 || true)
require_status "$http_code" "step at line 312"
location=$(echo "$response" | grep -iE '^Location:' | sed 's/Location: //i' | tr -d '\r' || true)

echo "HTTP $http_code, Location: $location"

if [[ "$http_code" != "302" ]]; then
    echo "FAIL: Expected 302, got $http_code"
    exit 1
fi

if ! echo "$location" | grep -qF -- "https://localhost:8443/realms/demo/protocol/openid-connect/logout"; then
    echo "FAIL: Expected redirect to Keycloak logout endpoint, got $location"
    exit 1
fi

if ! echo "$location" | grep -qF -- "id_token_hint="; then
    echo "FAIL: Missing id_token_hint parameter"
    exit 1
fi

if ! echo "$location" | grep -qF -- "post_logout_redirect_uri="; then
    echo "FAIL: Missing post_logout_redirect_uri parameter"
    exit 1
fi

# Follow the logout redirect with Keycloak jar
LOGOUT_REDIRECT="$location"
echo -n "    Following logout redirect... "

response=$(curl -s -i -c "$KC_JAR" -b "$KC_JAR" -L "$LOGOUT_REDIRECT" 2>/dev/null || true)
final_http_code=$(printf '%s\n' "${response%%$'\n'*}" | grep -oE '[0-9]{3}' | head -1 || true)
require_status "$final_http_code" "step at line 342"
final_location=$(echo "$response" | grep -iE '^Location:' | sed 's/Location: //i' | tr -d '\r' | tail -1 || true)

echo "HTTP $final_http_code"

# The final redirect should be back to the app
if ! echo "$final_location" | grep -qF -- "http://localhost:8001/"; then
    echo "FAIL: Expected redirect back to app, got $final_location"
    exit 1
fi

echo "OK"

# (7) Prove the PROVIDER session is gone: GET the original auth URL with the KC_JAR
# and assert the login form is shown again (status 200, page contains login-actions/authenticate)
echo -n "(7) GET original auth URL with KC jar... "

response=$(curl -s -i -c "$KC_JAR" -b "$KC_JAR" "$AUTH_URL" 2>/dev/null || true)
http_code=$(printf '%s\n' "${response%%$'\n'*}" | grep -oE '[0-9]{3}' | head -1 || true)
require_status "$http_code" "step at line 360"
body=$(echo "$response" | sed '1,/^$/d')  # Remove headers

echo "HTTP $http_code"

if [[ "$http_code" != "200" ]]; then
    echo "FAIL: Expected 200, got $http_code"
    exit 1
fi

if [[ "$body" != *"login-actions/authenticate"* ]]; then
    echo "FAIL: Expected login form (provider session should be gone), got redirect or different page"
    exit 1
fi

echo "OK"

echo "All tests passed for $FIREWALL"