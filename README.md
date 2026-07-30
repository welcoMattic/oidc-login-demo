# Symfony OIDC login demo (multi provider)

Demo application for the **OIDC Authorization Code Flow authenticator** proposed in
[symfony/symfony#64954](https://github.com/symfony/symfony/pull/64954), exercised
against several real Identity Providers running locally in Docker.

The app is wired to the `oidc-login-backbone` branch of a Symfony fork through the
monorepo `link` script, so the framework code under test is the branch itself.

## Status

| Provider | Login | Demo user | Notes |
| --- | --- | --- | --- |
| Keycloak 26.7 | works | `alice` / `password` | realm imported at boot, nothing else to do |
| Authentik 2026.5 | works | `bob` / `password` | needs `grant_types` + MFA stage removal, see below |
| Gravitee AM 4.11 | **not provisioned** | `carol` / `password` (planned) | stack boots, management API login unresolved |

## Requirements

- PHP 8.4+, Composer, [Symfony CLI](https://symfony.com/download)
- Docker with Compose
- A checkout of the Symfony fork on branch `oidc-login-backbone`

## Setup

```bash
composer install

# Link the framework branch under test into vendor/ (run from the app directory)
php /path/to/symfony/link .

# Start the IdPs you want (profiles keep memory usage sane)
docker compose -f compose.idp.yaml --profile keycloak up -d
docker compose -f compose.idp.yaml --profile authentik up -d
bash docker/authentik/provision.sh            # sets bob's password, unblocks the flow

symfony server:start -d --no-tls --port=8001
open http://localhost:8001/
```

The homepage is a provider chooser: each button leads to a page protected by that
provider's firewall, which triggers the OIDC redirect.

> The app must be served on **port 8001**: the registered redirect URIs point at
> `http://localhost:8001/<provider>/callback`.

## How it is wired

The backbone authenticator is **one provider per firewall**, so each IdP gets its own
firewall, URL prefix and callback (`config/packages/security.yaml`):

```yaml
keycloak:
    pattern: ^/keycloak
    provider: oidc
    oidc_login:
        provider_uri: '%env(OIDC_KEYCLOAK_PROVIDER_URI)%'
        client_id: '%env(OIDC_KEYCLOAK_CLIENT_ID)%'
        client_secret: '%env(OIDC_KEYCLOAK_CLIENT_SECRET)%'
        check_path: /keycloak/callback
```

The `oidc` user provider builds a self-contained `OidcUser` from the provider claims,
so **no database is involved** in authentication.

### Why the IdPs are published on localhost

The browser and the Symfony backend must reach each IdP at the **same host:port**: the
authenticator compares the discovery document's `issuer` with the configured
`provider_uri`. Publishing on `127.0.0.1` keeps both views identical. Container names
(`http://keycloak:8080`) would also be rejected by the factory, which requires HTTPS
for anything that is not a loopback or test host.

## Findings from building this demo

Things that were not obvious, and are worth knowing when using the branch:

1. **Env vars were rejected on `provider_uri`.** A node declared `cannotBeEmpty()` next
   to a validator makes Symfony refuse environment variables outright (*"cannot contain
   an environment variable when empty values are not allowed by definition and are
   validated"*). `client_id` and `client_secret` were always fine, having no validator.
   Fixed upstream on the branch: the HTTPS requirement is now checked at compile time
   for a literal, and by `OidcDiscovery` at runtime, which also covers env var values.
   This demo configures all three through `%env()%`.
2. **The callback route needs a manual import.** The branch ships an
   `OidcLoginRouteLoader` tagged `routing.route_loader`, but no recipe imports it (the
   logout loader is imported by the security-bundle recipe). Without the import added in
   `config/routes/security.yaml`, the provider redirect hits an unrouted URL and 404s.
3. **A trailing slash in the issuer broke discovery.** Authentik announces
   `.../application/o/symfony-demo/`; the factory `rtrim()`s the configured issuer, so
   the Discovery §4.3 check could never pass. Fixed upstream in the branch
   ("Ignore a trailing slash when checking the OIDC issuer"). Note that with an env var
   the `rtrim()` applies to the unresolved placeholder, so a trailing slash survives into
   the discovery URL (`...//.well-known/openid-configuration`); Authentik accepts it.
4. **`failure_path` is worth setting.** A failed login otherwise redirects to `/login`,
   which does not exist in this app.
5. Only the `openid` scope is requested by the backbone, so UserInfo may return little
   more than `sub` (configurable scopes/claims live in follow-up PRs).
6. Logout is **local only** (the session is cleared); RP-initiated logout against the
   provider's `end_session_endpoint` is a follow-up PR.

## Provider specifics

### Keycloak

`docker/keycloak/realm-demo.json` is imported at boot (`start-dev --import-realm`):
realm `demo`, confidential client `symfony-demo`, user `alice`. Because `start-dev`
uses an ephemeral H2 database, the realm is re-imported on every restart.

### Authentik

`docker/authentik/blueprints/symfony-demo.yaml` provisions the OAuth2 provider, the
application and the user. Two non-obvious requirements:

- `grant_types` **must be declared explicitly** (`authorization_code`). Recent versions
  default it to an empty list, and the authorization request is rejected with
  `invalid_request` / *"Invalid grant_type for provider"*.
- the stock `default-authentication-flow` binds an **MFA validation stage**, which
  stalls a password-only login. `docker/authentik/provision.sh` removes that binding
  and sets the demo user's password (a blueprint cannot express a password).

### Gravitee AM (incomplete)

The stack boots (`mongo` + `am-management-api` + `am-gateway`), which required finding
that all repositories are wired to the `${ds.mongodb.*}` placeholders: the
`gravitee_management_mongodb_uri` form documented in older guides is **ignored**, and it
silently falls back to `localhost:27017`. The working override is:

```yaml
gravitee_ds_mongodb_host: gravitee_mongo
gravitee_ds_mongodb_port: "27017"
gravitee_ds_mongodb_dbname: gravitee-am
```

What is **not** solved: authenticating against the management API to create the security
domain, the OIDC application and the user. `POST /management/auth/login` with
`admin` / `adminadmin` (the password documented in the shipped `gravitee.yml`) answers
`302 -> /management/auth/login?error`, with or without the XSRF token, and enabling the
in-memory provider (`gravitee_security_providers_0_enabled`) did not change it. The
`gravitee` firewall is configured but its provider is not reachable yet.

Note: Gravitee AM is still distributed as **separate images**; there is no all-in-one AM
image at 4.11.

## Layout

```
compose.idp.yaml                             the three IdP stacks, one Compose profile each
docker/keycloak/realm-demo.json              Keycloak realm, client and user
docker/authentik/blueprints/symfony-demo.yaml  Authentik provider, application and user
docker/authentik/provision.sh                password + MFA stage removal
config/packages/security.yaml                one oidc_login firewall per provider
config/routes/security.yaml                  imports the OIDC callback route loader
src/Controller/DemoController.php            chooser + per-provider profile pages
```
