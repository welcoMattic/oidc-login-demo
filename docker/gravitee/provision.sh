#!/usr/bin/env bash
# Provisions the Gravitee AM demo domain through the management API: a security domain,
# an OIDC application and a user. Idempotent, so "make start" can run it every time.
#
# Everything here was found the hard way; the four traps are commented below.
set -euo pipefail

cd "$(dirname "$0")/../.."
exec python3 - "$@" <<'PY'
import base64, json, sys, time, urllib.error, urllib.request

MGMT = "http://localhost:8093/management"
ENV = f"{MGMT}/organizations/DEFAULT/environments/DEFAULT"
# Trap 1: the admin password is "adminadmin", not "admin". The BCrypt hash is in the
# container's gravitee.yml, with "Password value: adminadmin" right above it.
ADMIN = "admin:adminadmin"
DOMAIN, CLIENT_ID, CLIENT_SECRET = "demo", "symfony-demo", "gravitee-demo-secret"
REDIRECT = "http://localhost:8001/gravitee/callback"
USER, PASSWORD = "carol", "Gravitee!2026"


def call(method, url, body=None, token=None, basic=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    if basic:
        req.add_header("Authorization", "Basic " + base64.b64encode(basic.encode()).decode())
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            raw = r.read()
            return r.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")
    except OSError as e:
        return 0, str(e)


def wait_for_management():
    for _ in range(60):
        st, _ = call("POST", f"{MGMT}/auth/token", basic=ADMIN)
        if st == 200:
            return
        time.sleep(5)
    sys.exit("the Gravitee management API never became reachable on :8093")


def items(payload):
    return payload.get("data", payload) if isinstance(payload, dict) else payload


wait_for_management()
st, tok = call("POST", f"{MGMT}/auth/token", basic=ADMIN)
token = tok["access_token"]

# Trap 2: AM 4.x refuses a domain without dataPlaneId ("must not be null"). "default" is
# the id declared by gravitee_dataPlanes_0_id in compose.idp.yaml.
st, dom = call("POST", f"{ENV}/domains",
               {"name": DOMAIN, "description": "Symfony OIDC login demo", "dataPlaneId": "default"},
               token=token)
if st in (400, 409):
    st, listing = call("GET", f"{ENV}/domains", token=token)
    dom = next((d for d in items(listing) if d["name"] == DOMAIN), None)
    if dom is None:
        sys.exit(f"cannot create or find the domain: {st} {listing}")
    print(f"gravitee: domain {DOMAIN} already provisioned")
elif st not in (200, 201):
    sys.exit(f"domain creation failed: {st} {dom}")
else:
    print(f"gravitee: domain {DOMAIN} created")

did = dom["id"]
call("PATCH", f"{ENV}/domains/{did}", {"enabled": True}, token=token)

# Trap 3: a redirect URI on localhost, or on plain http, is rejected as "localhost is
# forbidden" until the domain says otherwise. The app itself runs on http://localhost:8001.
call("PATCH", f"{ENV}/domains/{did}",
     {"oidc": {"clientRegistrationSettings": {
         "allowLocalhostRedirectUri": True, "allowHttpSchemeRedirectUri": True,
         "allowWildCardRedirectUri": False,
         "isDynamicClientRegistrationEnabled": False,
         "isOpenDynamicClientRegistrationEnabled": False}}},
     token=token)

st, app = call("POST", f"{ENV}/domains/{did}/applications",
               {"name": CLIENT_ID, "type": "WEB", "clientId": CLIENT_ID,
                "clientSecret": CLIENT_SECRET, "redirectUris": [REDIRECT]},
               token=token)
if st in (400, 409):
    st, listing = call("GET", f"{ENV}/domains/{did}/applications", token=token)
    if next((a for a in items(listing) if a["name"] == CLIENT_ID), None) is None:
        sys.exit(f"cannot create or find the application: {st} {listing}")
    print(f"gravitee: application {CLIENT_ID} already provisioned")
elif st not in (200, 201):
    sys.exit(f"application creation failed: {st} {app}")
else:
    print(f"gravitee: application {CLIENT_ID} created")

# Trap 4: the user must carry the IDENTITY PROVIDER ID as its "source". Leaving it out
# stores the provider's display name instead, and the login flow then answers
# "invalid_user" for a user that is plainly there in the console.
st, idps = call("GET", f"{ENV}/domains/{did}/identities", token=token)
if st != 200 or not idps:
    sys.exit(f"cannot list the domain identity providers: {st} {idps}")
source = idps[0]["id"]

# Trap 5: the default password policy is the OWASP one, twelve characters minimum, so a
# shorter password is refused even with an upper case, a digit and a special character.
st, res = call("POST", f"{ENV}/domains/{did}/users",
               {"username": USER, "password": PASSWORD, "firstName": "Carol",
                "lastName": "Demo", "email": "carol@gravitee.demo",
                "preRegistration": False, "source": source},
               token=token)
if st in (200, 201):
    print(f"gravitee: user {USER} created")
elif st in (400, 409):
    print(f"gravitee: user {USER} already provisioned")
else:
    sys.exit(f"user creation failed: {st} {res}")

# Trap 6: the password passed at creation does not make the user able to log in; the
# gateway answers "invalid_user" until the password is set through resetPassword. Doing
# it unconditionally also repairs a user left behind by an earlier run.
st, listing = call("GET", f"{ENV}/domains/{did}/users", token=token)
uid = next((u["id"] for u in items(listing) if u["username"] == USER), None)
if uid is None:
    sys.exit(f"the user {USER} cannot be found after creation: {listing}")
st, res = call("POST", f"{ENV}/domains/{did}/users/{uid}/resetPassword", {"password": PASSWORD}, token=token)
if st not in (200, 204):
    sys.exit(f"setting the password failed: {st} {res}")
print(f"gravitee: password set for {USER}")
print(f"gravitee: ready, issuer https://localhost:9443/{DOMAIN}/oidc")
PY
