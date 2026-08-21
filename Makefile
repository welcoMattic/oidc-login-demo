# Symfony OIDC login demo.
#
#   make start SYMFONY_SRC=/path/to/symfony   first run, links the framework branch
#   make start                                afterwards
#   make stop
#
# "make" with no target lists everything.

# Path to a checkout of the Symfony fork on branch oidc-login-tuning. Only needed the
# first time: the symlinks it creates in vendor/ are reused afterwards.
SYMFONY_SRC ?=

# The app must stay on this port: the redirect URIs registered with the providers point
# at http://localhost:8001/<provider>/callback. Change it in the IdP seeds as well.
APP_PORT = 8001

# The Identity Providers to run. "make start IDP=keycloak" starts only that one.
IDP ?= keycloak authentik

COMPOSE = docker compose -f compose.idp.yaml
PROFILES = $(foreach profile,$(IDP),--profile $(profile))

.DEFAULT_GOAL = help
.PHONY: help start stop restart idp certs link serve check logs clean

help: ## List the available targets
	@grep -hE '^[a-z-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2}'
	@echo
	@echo "  first run: make start SYMFONY_SRC=/path/to/symfony"

start: certs vendor/autoload.php link idp serve ## Start everything, then open http://localhost:8001/
	@echo
	@echo "  Ready: http://localhost:$(APP_PORT)/"
	@echo "  Keycloak: alice / password, authentik: bob / password"
	@echo

stop: ## Stop the web server and every container
	-symfony server:stop
	$(COMPOSE) --profile all down --remove-orphans

restart: stop start ## Stop everything, then start it again

certs: ## Generate the TLS certificate the Identity Providers are served with
	@docker/generate-certs.sh

vendor/autoload.php:
	composer install --no-interaction

link: ## Link the framework branch under test into vendor/
	@if [ -n "$(SYMFONY_SRC)" ]; then \
		echo "linking the framework from $(SYMFONY_SRC)"; \
		php $(SYMFONY_SRC)/link . | tail -1; \
	elif [ -L vendor/symfony/security-bundle ]; then \
		echo "framework already linked: $$(readlink vendor/symfony/security-bundle)"; \
	else \
		echo "ERROR: the OIDC login authenticator is not released yet, so the demo needs"; \
		echo "the framework branch. Pass the path to your Symfony checkout:"; \
		echo; \
		echo "    make start SYMFONY_SRC=/path/to/symfony"; \
		exit 1; \
	fi

idp: certs ## Start the Identity Providers and provision them
	$(COMPOSE) $(PROFILES) up -d --wait
	@if echo "$(IDP)" | grep -q authentik; then docker/authentik/provision.sh; fi

serve: ## (Re)start the web server on port 8001
	@symfony server:stop >/dev/null 2>&1 || true
	@symfony server:start -d --no-tls --port=$(APP_PORT)

check: ## Prove the wiring: container, firewalls and callback routes
	php bin/console lint:container
	php bin/console debug:firewall
	php bin/console debug:router | grep -E 'oidc_login_callback|_logout_'

logs: ## Follow the Identity Providers' logs
	$(COMPOSE) --profile all logs -f --tail=50

clean: stop ## Also drop the containers' data and the generated certificates
	$(COMPOSE) --profile all down -v --remove-orphans
	rm -rf docker/certs var/cache var/log
