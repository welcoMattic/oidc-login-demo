# Symfony OIDC login demo

Demo application for the **OIDC Authorization Code Flow authenticator**
([symfony/symfony#64954](https://github.com/symfony/symfony/pull/64954)), exercised
against real Identity Providers running locally in Docker.

Two firewalls, configured differently, cover the whole `oidc_login` option set between
them. After logging in, the page shows the resulting user, its roles and every claim,
next to the options that produced them.

## Try it

Ensure to have Symfony source code checked out on the branch reference in [symfony/symfony#64954](https://github.com/symfony/symfony/pull/64954)
to be able to run the demo locally.

```bash
git clone https://github.com/welcoMattic/oidc-login-demo && cd oidc-login-demo
make start SYMFONY_SRC=/path/to/symfony/source/code/itself
```

Then open <http://localhost:8001/>, click *Log in with Keycloak* and use
**alice / password**. That is the whole thing: two commands and a login form.

`make start` generates a TLS certificate, installs the dependencies, links the framework
branch into `vendor/`, starts the Identity Providers, provisions them and starts the web
server. Later runs need no `SYMFONY_SRC`. `make` on its own lists the other targets, and
`make stop` shuts everything down.

Without a browser, `make smoke` logs in through both providers and checks the result:
the authorization request and its PKCE challenge, the code exchange, the claims on the
page and the logout. `make check` lints the container and lists the firewalls and the
callback routes.

### Requirements

- PHP 8.4+, Composer, [Symfony CLI](https://symfony.com/download), Docker with Compose
- a checkout of the Symfony fork on the tip of the `oidc_login` stack, currently
  `oidc-login-idtoken-signature`, which carries the whole option set. The demo links to
  that working tree, so the branch it is on **is** the code under test. `make start` checks
  it on every run and refuses to boot on another layer, since the config here uses options
  the lower layers do not know. To run against another layer on purpose, pass
  `SYMFONY_BRANCH=<branch>`.
- optional: [mkcert](https://github.com/FiloSottile/mkcert). With `mkcert -install` run
  once, the browser trusts the demo certificate and the IdP pages open without a warning.
  Without mkcert, an `openssl` self-signed certificate is used and the browser asks to
  accept it once per provider.

The app must stay on port **8001**: the redirect URIs registered with the providers point
at `http://localhost:8001/<provider>/callback`.

## Providers

| Provider                     | Status               | Demo user            | Provisioning                                                                                                            |
|------------------------------|----------------------|----------------------|-------------------------------------------------------------------------------------------------------------------------|
| Keycloak 26.7                | works out of the box | `alice` / `password` | realm, client and user imported at boot from `docker/keycloak/realm-demo.json`                                          |
| authentik 2026.5             | works out of the box | `bob` / `password`   | provider, application and user from a blueprint, plus `docker/authentik/provision.sh` for the password and one flow fix |
| Keycloak, as a public client | works out of the box | `alice` / `password` | second client `symfony-demo-public` in the same realm import, seeded with `publicClient: true`                          |
| Gravitee AM                  | **not included**     | none                 | see below, the stack boots but cannot be provisioned                                                                    |

Neither provider asks you to click through an admin UI. Their admin consoles are there if
you want to look: Keycloak on <https://localhost:8443/admin/> (`admin` / `admin`),
authentik on <http://localhost:9100/if/admin/> (`akadmin` / `admin12345`).

## What each option does, and where to see it

| Option | Where | What it shows |
| --- | --- | --- |
| `provider_uri`, `client_id`, `client_secret` | keycloak, authentik | the required options, read from `.env` through `%env()%`. `client_secret` is required unless the client is public |
| `check_path` | both | the callback path, matching the redirect URI registered with the provider |
| `scope` | both | `profile` and `email` on top of the mandatory `openid`, which is what makes a name and an email show up |
| `user_identifier_claim` | keycloak (`email`) | the identity becomes `alice@keycloak.demo` instead of the `sub` UUID |
| `user_data_source` | keycloak (`userinfo`), authentik (`id_token`) | claims fetched from the UserInfo endpoint, or decoded from the ID token with no extra round trip |
| `enable_end_session`, `post_logout_redirect_path` | both | logging out ends the session at the provider too, then comes back to `/` |
| `token_endpoint_auth_method` | keycloak (`client_secret_basic`), authentik (`client_secret_post`), public (`none`) | the secret sent as HTTP Basic credentials, in the request body, or no secret sent at all |
| `client_secret` omitted | public | a public client identifies itself with `client_id` alone, PKCE does the binding |
| `id_token_signature.required`, `.algorithms` | keycloak (spelled out), others (default) | the ID token signature checked against the provider JWKS, with an allowlist that never holds `none` |
| `pkce.enabled`, `pkce.method` | keycloak | the `code_challenge` in the authorization request, and the verifier sent back at the exchange |
| `direct_redirect` | both (`true`) | the entry point goes straight to the provider, the "Log in with..." behaviour |
| `discovery_cache_ttl` | both (60) | short, because these containers re-import their configuration when they restart |
| `allowed_time_drift` | both (5) | tolerance on the ID token time claims, which a container clock drifting from the host's is enough to break |
| `prompt`, `max_age`, `authorization_params` | commented in `security.yaml` | the demo has no use for them, but the syntax is there |

## How it is wired

One firewall per provider: an `oidc_login` firewall talks to a single provider, so each
one owns a URL prefix, a callback path and an entry point.

The **callback route must be imported by hand**, in `config/routes/security.yaml`:

```yaml
_oidc_login_callbacks:
    resource: security.authenticator.oidc_login.route_loader
    type: service
```

Without it the provider's redirect lands on an unrouted `/<provider>/callback` and gets a
404: the router runs before the firewall. The feature ships the loader (tagged
`routing.route_loader`, one route per firewall) but no Flex recipe imports it yet, unlike
the logout loader right above it in the same file.

The `oidc` user provider builds a self-contained `OidcUser` from the claims, so **no
database is involved** anywhere in this demo.

### Mapping claims onto roles

Roles stay `[ROLE_USER]`, by design: the built-in `oidc` provider drops a `roles` claim
and never lets a claim define the identity, so a provider cannot hand out Symfony roles.
Mapping them is your own provider's job, and it receives every claim:

```php
final class MyOidcUserProvider implements AttributesBasedUserProviderInterface
{
    public function loadUserByIdentifier(string $identifier, array $attributes = []): UserInterface
    {
        $roles = array_map(static fn (string $group) => 'ROLE_'.strtoupper($group), $attributes['groups'] ?? []);

        return new MyUser($identifier, ['ROLE_USER', ...$roles], $attributes);
    }
    // ...
}
```

Then point the firewall at it with `provider: my_oidc` instead of `provider: oidc`.

### Why the Identity Providers are served over HTTPS

Two reasons, and the first one is not optional:

1. **The authenticator requires the token endpoint announced by the provider to use
   HTTPS.** That leg carries the authorization code and the PKCE verifier one way, and
   returns the ID and access tokens the other, so plain HTTP would expose all of it.
   `OidcDiscovery::getSecureEndpoint()` exempts loopback hosts for the issuer and the other
   endpoints, but not for the token endpoint, so an IdP on `http://localhost` fails the code
   exchange. Every provider here is therefore published on `https://localhost:<port>`, with
   a certificate generated by `docker/generate-certs.sh` and trusted through
   `config/packages/http_client.yaml`. Note that `cafile` there points at a bundle holding
   the system roots **plus** the demo CA: pointing it at the demo CA alone replaces the
   system bundle for every outbound request, which breaks anything else the app calls
   (`importmap:install` fetching from a CDN, to name the one that bit us).
2. The browser and the Symfony backend must reach a provider at the very same
   `host:port`, because the `issuer` announced in the discovery document is compared with
   the configured `provider_uri`. Publishing on `127.0.0.1` keeps both views identical.

Keycloak serves HTTPS itself. authentik terminates TLS with a certificate of its own
making, which nothing else trusts, so a small Caddy front (`docker/authentik/Caddyfile`)
presents the demo certificate instead.

## Findings from building this demo

Things that were not obvious, and are worth knowing when using the branch:

1. **A local IdP cannot be served over plain HTTP any more**, per the HTTPS rule above.
   This demo worked over HTTP until the endpoint hardening landed; it now needs TLS on
   every provider, which is a real cost for anyone trying the feature locally. Either the
   loopback exemption should extend to the token endpoint for local development, or the
   documentation should say plainly that a local IdP needs TLS.
2. **`direct_redirect` defaults to `false`**, and then the entry point redirects to
   `login_path` (`/login` by default). An app with a "Log in with..." button and no login
   page of its own gets a 404 until it sets `direct_redirect: true`.
3. **The callback route needs a manual import**, as described above. The real fix belongs
   in `symfony/recipes`.
4. **Environment variables were rejected on `provider_uri`.** A node declared
   `cannotBeEmpty()` next to a validator makes the Config component refuse environment
   variables outright. Fixed on the branch: the HTTPS requirement is checked at compile
   time for a literal value, and by `OidcDiscovery` at runtime, which also covers values
   that only exist then. This demo configures all three required options through `%env()%`.
5. **A trailing slash in the issuer broke discovery.** authentik announces
   `.../application/o/symfony-demo/`, and the expected issuer was trimmed. Fixed on the
   branch, on both sides of the comparison.
6. **`failure_path` is worth setting.** A failed login otherwise goes to `login_path`,
   which does not exist in an app like this one.
7. **`user_identifier_claim` must point at a claim the provider actually returns**, and it
   only returns the ones the requested `scope` covers. `user_identifier_claim: email`
   without `email` in the scope fails the login with a clear message.
8. **The end of an RP-Initiated Logout is the provider's call, not Symfony's.** The same
   configuration gives two different endings: Keycloak follows the
   `post_logout_redirect_uri` and the browser lands back on the app, while authentik's
   stock invalidation flow ends on its own "You've logged out" page, with a link back to
   the application. Both are logged out; only the last hop differs.
9. **Public clients need no secret at all.** The `public` firewall shows it:
   `token_endpoint_auth_method: none`, no `client_secret` key, and a Keycloak client seeded
   with `publicClient: true`. PKCE is then the only thing binding the authorization code to
   the client, so the branch refuses `pkce.enabled: false` there, and refuses to turn the ID
   token signature check off as well: nothing else would be left. `bin/smoke-public-client.sh`
   walks that flow end to end.
10. **The ID token signature is verified against the provider's JWKS**, and this is the
   default. The `keycloak` firewall spells the options out (`id_token_signature.required`
   and an `algorithms` allowlist that can never contain `none`) so the surface is visible;
   the other two rely on the default. Verifying it means the app fetches the provider JWKS
   through the same `http_client`, which is one more reason the trust bundle above has to be
   right.

### Gravitee AM, not included

The stack boots (`compose.gravitee-wip.yaml`), which took finding that all its
repositories are wired to the `${ds.mongodb.*}` placeholders: the
`gravitee_management_mongodb_uri` form found in older guides is **ignored** and silently
falls back to `localhost:27017`. What is not solved is provisioning it:
`POST /management/auth/login` with `admin` / `adminadmin` (the password shipped in
`gravitee.yml`) answers `302 -> ?error`, with and without the XSRF token, and with the
in-memory provider explicitly enabled. Five approaches failed. It would also need a TLS
front now. Rather than leave a button that leads nowhere, the provider is out of the demo
until someone gets past that.

## Layout

```
Makefile                                       one command to start everything
bin/smoke-keycloak.sh, bin/smoke-authentik.py  browserless end-to-end logins
compose.idp.yaml                               Keycloak and authentik, one Compose profile each
compose.gravitee-wip.yaml                      the unfinished Gravitee AM stack
docker/generate-certs.sh                       the certificate the providers are served with
docker/keycloak/realm-demo.json                Keycloak realm, client and user
docker/authentik/blueprints/symfony-demo.yaml  authentik provider, application and user
docker/authentik/provision.sh                  password, flow fix, and a discovery dump
docker/authentik/Caddyfile                     TLS front for authentik
config/packages/security.yaml                  one oidc_login firewall per provider
config/packages/http_client.yaml               trusts the demo certificate
config/routes/security.yaml                    imports the OIDC callback route loader
src/Controller/DemoController.php              provider chooser and per-provider profile page
```
