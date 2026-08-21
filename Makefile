# Symfony OIDC login demo.
#
#   make start SYMFONY_SRC=/path/to/symfony   first run, links the framework branch
#   make start                                afterwards
#   make stop
#
# "make" with no target lists everything.

# Path to a checkout of the Symfony fork. Only needed the first time: the symlinks it
# creates in vendor/ are reused afterwards.
SYMFONY_SRC ?=

# The branch the demo expects to be linked. It is the tip of the stacked series, so the
# whole option set is available. Checked on every start, because linking silently follows
# whatever the checkout is on. Pass SYMFONY_BRANCH= (empty) to skip the check.
SYMFONY_BRANCH ?= oidc-login-idtoken-signature

# The app must stay on this port: the redirect URIs registered with the providers point
# at http://localhost:8001/<provider>/callback. Change it in the IdP seeds as well.
APP_PORT = 8001

# The Identity Providers to run. "make start IDP=keycloak" starts only that one.
IDP ?= keycloak authentik

COMPOSE = docker compose -f compose.idp.yaml
PROFILES = $(foreach profile,$(IDP),--profile $(profile))

.DEFAULT_GOAL = help
.PHONY: help start stop restart idp certs link warmup serve check smoke logs clean

help: ## List the available targets
	@grep -hE '^[a-z-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2}'
	@echo
	@echo "  first run: make start SYMFONY_SRC=/path/to/symfony"

start: certs vendor/autoload.php link warmup idp serve ## Start everything, then open http://localhost:8001/
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
	# --no-scripts on purpose: the post-install cache:clear would read a security.yaml
	# that uses options only the linked branch knows, and fail before "link" ever runs
	composer install --no-interaction --no-scripts

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
	@if [ -n "$(SYMFONY_BRANCH)" ]; then \
		src=$${SYMFONY_SRC:-$$(cd "$$(dirname "$$(readlink vendor/symfony/security-bundle)")/../../.." && pwd)}; \
		on=$$(git -C "$$src" rev-parse --abbrev-ref HEAD 2>/dev/null); \
		if [ "$$on" != "$(SYMFONY_BRANCH)" ]; then \
			echo; \
			echo "ERROR: the linked Symfony checkout is on \"$$on\", not \"$(SYMFONY_BRANCH)\"."; \
			echo "The demo configures options that only exist on that branch, so the app"; \
			echo "would fail to boot. Either:"; \
			echo "    git -C $$src checkout $(SYMFONY_BRANCH)"; \
			echo "or, to run against another layer on purpose:"; \
			echo "    make start SYMFONY_BRANCH=$$on"; \
			exit 1; \
		fi; \
		echo "linked branch: $$on"; \
	fi

warmup: ## Build the container and fetch the front-end assets, once the branch is linked
	php bin/console cache:clear --no-interaction
	# a fresh clone has no assets/vendor/ (gitignored), and the profile page needs Stimulus
	php bin/console importmap:install

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

smoke: ## Log in through every provider without a browser, and check the result
	bin/smoke-keycloak.sh
	bin/smoke-authentik.py
	bin/smoke-public-client.sh

logs: ## Follow the Identity Providers' logs
	$(COMPOSE) --profile all logs -f --tail=50

clean: stop ## Also drop the containers' data and the generated certificates
	$(COMPOSE) --profile all down -v --remove-orphans
	rm -rf docker/certs var/cache var/log
