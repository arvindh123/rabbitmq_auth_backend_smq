RABBITMQ_DIR := rabbitmq-server
CURRENT_DIR := $(notdir $(CURDIR))
DEST_DIR := $(RABBITMQ_DIR)/deps/$(CURRENT_DIR)
RABBITMQ_VERSION := v4.1.4


define make_docker
docker build \
	-t supermq/rabbitmq:$(RABBITMQ_VERSION) \
	-t supermq/rabbitmq:latest \
	-f docker/Dockerfile .
endef

.ONESHELL:

.PHONY: all deps clone copy makefile  build run clean clean-smq-auth

# Default target
all: deps
	@echo "Running default make in $(DEST_DIR)"
	@$(MAKE) -C $(DEST_DIR)

deps: clone copy makefile
	@set -e; \
	make -C $(DEST_DIR) deps; \
	rm -rf deps; \
	mkdir -p deps; \
	cp -r $(RABBITMQ_DIR)/deps/* deps/;

clone:
	@if [ ! -d "$(RABBITMQ_DIR)" ]; then \
		git clone --branch $(RABBITMQ_VERSION) --depth 1 https://github.com/rabbitmq/rabbitmq-server.git $(RABBITMQ_DIR); \
	else \
		echo "$(RABBITMQ_DIR) already exists, skipping clone"; \
	fi

# Step 2: Copy current directory into deps/<current_dir_name>
copy:
	@mkdir -p $(DEST_DIR)
	@git ls-files -z  | rsync -av --ignore-missing-args --files-from=- --from0 ./ $(DEST_DIR)/

makefile:
	@echo "Creating Makefile in $(DEST_DIR)"
	@mkdir -p $(DEST_DIR)
	@cat > $(DEST_DIR)/Makefile << EOF
		PROJECT = rabbitmq_auth_backend_smq
		PROJECT_DESCRIPTION = RabbitMQ SMQ Authentication Backend
		PROJECT_MOD = rabbitmq_auth_backend_smq_app
		RABBITMQ_VERSION := v4.1.4
		RABBITMQ_REPO    := https://github.com/rabbitmq/rabbitmq-server
		RABBITMQ_BUILD_DIR := build-env

		DEPS = rabbit_common rabbit amqp_client smq_auth
		TEST_DEPS = rabbitmq_ct_helpers rabbitmq_ct_client_helpers

		DEP_EARLY_PLUGINS = rabbit_common/mk/rabbitmq-early-plugin.mk
		DEP_PLUGINS = rabbit_common/mk/rabbitmq-plugin.mk

		dep_smq_auth = git https://github.com/arvindh123/smq_auth.git master

		## skip unused vars as error
		ERLC_OPTS +=  +warn_unused_vars

		# FIXME: Use erlang.mk patched for RabbitMQ, while waiting for PRs to be
		# reviewed and merged.

		ERLANG_MK_REPO = https://github.com/rabbitmq/erlang.mk.git
		ERLANG_MK_COMMIT = rabbitmq-tmp

		include ../../rabbitmq-components.mk
		include ../../erlang.mk
	EOF


build: deps
	@set -e; \
	make -C $(DEST_DIR) dist; \
	rm -rf plugins; \
	mkdir -p plugins; \
	cp -r $(DEST_DIR)/plugins/* plugins/; \
	$(call make_docker)

run:
	docker compose -p smq_rabbit_$(subst .,_,$(RABBITMQ_VERSION)) -f docker/docker-compose.yaml up

clean:
	rm -rf deps
	rm -rf plugins
	rm -rf rabbitmq-server

clean-smq-auth:
	rm -rf rabbitmq-server/deps/smq-auth
