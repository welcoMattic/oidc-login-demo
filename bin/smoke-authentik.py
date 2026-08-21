#!/usr/bin/env python3
"""Logs in through authentik without a browser, and checks what came out of it.

Usage: bin/smoke-authentik.py   (needs "make start" to have run)

authentik's login is a single page application, so there is no form to post: the
stages are driven through its flow executor API, which answers a JSON challenge at
each step.
"""
import http.cookiejar
import html
import json
import os
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

APP = "http://localhost:8001"
IDP = "https://localhost:9443"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

context = ssl.create_default_context(cafile=os.path.join(ROOT, "docker/certs/ca.crt"))
jar = http.cookiejar.CookieJar()


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


opener = urllib.request.build_opener(
    urllib.request.HTTPSHandler(context=context),
    urllib.request.HTTPCookieProcessor(jar),
    NoRedirect,
)

failures = []


def check(ok, label, detail=""):
    print(("OK: " if ok else "FAIL: ") + label + ((" " + detail) if detail else ""))
    if not ok:
        failures.append(label)


def call(url, data=None, headers=None):
    """Returns (status, headers, body), never following redirects."""
    try:
        response = opener.open(urllib.request.Request(url, data=data, headers=headers or {}))
        return response.status, response.headers, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.headers, error.read()


def cookie(name):
    return next((c.value for c in jar if c.name == name), None)


print("=== 1. GET /authentik while anonymous, expect a redirect to the provider")
status, headers, _ = call(APP + "/authentik")
authorization = headers.get("location", "")
check(status == 302 and authorization.startswith(IDP + "/application/o/authorize/"),
      "authorization endpoint, over https", authorization[:60])
for param in ("response_type=code", "code_challenge=", "code_challenge_method=S256",
              "state=", "nonce=", "scope=openid%20profile%20email"):
    check(param in authorization, param)

print("\n=== 2. Follow the authorization request")
status, headers, _ = call(authorization)
flow = headers.get("location", "")
check(status == 302 and "/if/flow/default-authentication-flow/" in flow,
      "the provider hands over to its authentication flow")

print("\n=== 3. Drive the flow executor: identify, then authenticate")
executor = (IDP + "/api/v3/flows/executor/default-authentication-flow/?query="
            + urllib.parse.quote(urllib.parse.urlparse(flow).query))
status, headers, body = call(executor)
challenge = json.loads(body)
answers = {
    "ak-stage-identification": {"uid_field": "bob"},
    "ak-stage-password": {"password": "password"},
}
final = None
for _ in range(8):
    component = challenge.get("component")
    print("   stage: " + str(component))
    if component == "xak-flow-redirect":
        final = challenge
        break
    if component not in answers:
        check(False, "the flow only asks for an identifier and a password", str(component))
        break
    request_headers = {"Content-Type": "application/json"}
    csrf = cookie("authentik_csrf")
    if csrf:
        request_headers["X-authentik-CSRF"] = csrf
    payload = json.dumps({"component": component, **answers[component]}).encode()
    status, headers, body = call(executor, data=payload, headers=request_headers)
    if status == 302:
        status, headers, body = call(urllib.parse.urljoin(IDP, headers.get("location")))
    challenge = json.loads(body)

check(final is not None, "the flow completed")
if final is None:
    sys.exit(1)

print("\n=== 4. Follow the flow back through the authorization endpoint")
status, headers, _ = call(urllib.parse.urljoin(IDP, final.get("to", "")))
callback = headers.get("location", "")
check(status == 302 and callback.startswith(APP + "/authentik/callback"),
      "sent back to the app callback with a code")

print("\n=== 5. GET the callback, where the authenticator runs")
status, headers, body = call(callback)
check(status == 302 and headers.get("location") == APP + "/authentik",
      "authenticated, redirected to default_target_path", str(headers.get("location")))
if status != 302:
    print(body.decode(errors="replace")[:1500])
    sys.exit(1)

print("\n=== 6. GET the profile page")
status, headers, body = call(APP + "/authentik")
page = html.unescape(body.decode())
text = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", page))
check(status == 200, "the profile page renders", str(status))
check("Symfony\\Component\\Security\\Core\\User\\OidcUser" in text, "the user is an OidcUser")
check("Roles ROLE_USER" in text, "roles are ROLE_USER, no claim granted any")
check(re.search(r"User identifier [0-9a-f]{20,}", text) is not None,
      "the identity is the sub claim")
check("Bob Authentik" in text, "the profile scope brought the name claim")
check("bob@authentik.demo" in text, "the email scope brought the email claim")
check('"nonce"' in page, "the ID token claims are displayed")
check("no UserInfo request" in text, "the claims came from the ID token")

print("\n=== 7. Log out, expect RP-Initiated Logout at the provider")
status, headers, _ = call(APP + "/authentik/logout")
logout = headers.get("location", "")
check(status == 302 and logout.startswith(IDP + "/application/o/symfony-demo/end-session/"),
      "end_session_endpoint")
check("id_token_hint=" in logout, "with an id_token_hint")
check("post_logout_redirect_uri=" in logout, "with a post_logout_redirect_uri")

print("\n=== 8. Follow the provider logout")
status, headers, _ = call(logout)
invalidation = headers.get("location", "")
check(status == 302 and "/if/flow/" in invalidation, "authentik runs its invalidation flow")
slug = invalidation.split("/if/flow/")[1].split("/")[0]
status, headers, body = call(IDP + "/api/v3/flows/executor/%s/?query=%s"
                             % (slug, urllib.parse.quote(urllib.parse.urlparse(invalidation).query)))
challenge = json.loads(body)
# Unlike Keycloak, authentik's stock invalidation flow does not follow the
# post_logout_redirect_uri: it ends on its own page, with a link back to the app.
check(challenge.get("component") == "ak-stage-session-end",
      "it ends on authentik's own page (post_logout_redirect_uri is not followed)",
      str(challenge.get("application_launch_url")))

print("\n=== 9. The session is gone, the flow starts over")
status, headers, _ = call(APP + "/authentik")
check(status == 302 and headers.get("location", "").startswith(IDP), "anonymous again")

print()
if failures:
    print("FAILED: " + ", ".join(failures))
    sys.exit(1)
print("authentik: everything checked out.")
