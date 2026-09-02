#!/usr/bin/env bash
# Generates the TLS certificate the demo Identity Providers are served with.
#
# The OIDC login authenticator requires the *token endpoint* announced by the provider
# to use HTTPS: the token endpoint carries the authorization code and the PKCE verifier
# one way and returns the ID and access tokens the other, so plain HTTP would expose
# all of it. The ID token signature is verified against the provider JWKS on top of that.
# A local IdP therefore cannot be served over plain HTTP, and every provider in this
# demo is published on https://localhost:<port>.
#
# Output (generated once, all of it gitignored):
#   docker/certs/idp.crt   the certificate the IdPs present, valid for localhost
#   docker/certs/idp.key   its private key
#   docker/certs/ca.crt    the CA the app trusts (config/packages/http_client.yaml)
#
# mkcert is used when it is installed, so browsers trust the certificate too (run
# "mkcert -install" once, this script never does it for you). Without mkcert, openssl
# generates a self-signed certificate and the browser asks to accept it once per IdP.
set -euo pipefail

cd "$(dirname "$0")/.."
dir=docker/certs
mkdir -p "$dir"

# The app trusts the IdPs through framework.http_client.default_options.cafile, which
# REPLACES the system CA bundle for every outbound request. Pointing it at the demo CA
# alone would break every other HTTPS call the app makes (importmap:install fetching
# from a CDN, for one), so what we hand it is the system roots plus the demo CA.
write_bundle() {
    system=$(php -r 'echo openssl_get_cert_locations()["default_cert_file"] ?? "";' 2>/dev/null)
    if [ -z "$system" ] || [ ! -r "$system" ]; then
        for candidate in /etc/ssl/cert.pem /etc/ssl/certs/ca-certificates.crt \
                         /etc/pki/tls/certs/ca-bundle.crt /usr/local/etc/openssl/cert.pem; do
            [ -r "$candidate" ] && system="$candidate" && break
        done
    fi
    if [ -z "$system" ] || [ ! -r "$system" ]; then
        echo "WARNING: no system CA bundle found, the app will only trust the demo CA"
        cp "$dir/ca.crt" "$dir/bundle.crt"
        return
    fi
    cat "$system" "$dir/ca.crt" > "$dir/bundle.crt"
    echo "trust bundle: system roots ($system) plus the demo CA"
}

if [ -f "$dir/idp.crt" ] && [ -f "$dir/idp.key" ] && [ -f "$dir/ca.crt" ]; then
    echo "certificates already present in $dir (delete the directory to regenerate)"
    write_bundle
    exit 0
fi

if command -v mkcert >/dev/null 2>&1; then
    echo "generating a certificate with mkcert..."
    mkcert -cert-file "$dir/idp.crt" -key-file "$dir/idp.key" localhost 127.0.0.1 ::1
    cp "$(mkcert -CAROOT)/rootCA.pem" "$dir/ca.crt"
    echo "using the mkcert CA; if the browser still warns, run: mkcert -install"
else
    echo "mkcert is not installed, falling back to a self-signed certificate..."
    openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes \
        -keyout "$dir/idp.key" -out "$dir/idp.crt" \
        -subj "/CN=localhost" \
        -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null
    cp "$dir/idp.crt" "$dir/ca.crt"
    echo "self-signed certificate: the browser asks to accept it once per IdP"
fi

# the IdP containers run as a non-root user and read the key through the bind mount
chmod 644 "$dir/idp.key"

write_bundle

echo "done: $dir/idp.crt, $dir/idp.key, $dir/ca.crt, $dir/bundle.crt"
