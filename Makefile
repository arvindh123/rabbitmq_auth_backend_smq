RABBITMQ_DIR := rabbitmq-server
PLUGINS = rabbitmq_auth_backend_supermq rabbitmq_auth_mechanism_supermq_mtls
RABBITMQ_PLUGIN_DIR := $(RABBITMQ_DIR)/deps
RABBITMQ_VERSION := v4.1.4


define make_docker
docker build \
	-t supermq/rabbitmq:$(RABBITMQ_VERSION) \
	-t supermq/rabbitmq:latest \
	-f docker/Dockerfile .
endef

.ONESHELL:

.PHONY: all deps clone copy build run clean clean-smq-auth

# Default target
all: deps
	@echo "Running make for RabbitMQ plugins..."
	@for plugin in $(PLUGINS); do \
		echo "Building $$plugin..."; \
		$(MAKE) -C $(RABBITMQ_PLUGIN_DIR)/$$plugin; \
	done

deps: clone copy
	@set -e; \
	for plugin in $(PLUGINS); do \
		echo "Fetching deps for $$plugin..."; \
		make -C $(RABBITMQ_PLUGIN_DIR)/$$plugin deps; \
	done
	rm -rf deps; \
	mkdir -p deps; \
	rsync -a $(foreach plugin,$(PLUGINS),--exclude=$(plugin)) $(RABBITMQ_PLUGIN_DIR)/ deps/;

clone:
	@if [ ! -d "$(RABBITMQ_DIR)" ]; then \
		git clone --branch $(RABBITMQ_VERSION) --depth 1 https://github.com/rabbitmq/rabbitmq-server.git $(RABBITMQ_DIR); \
	else \
		echo "$(RABBITMQ_DIR) already exists, skipping clone"; \
	fi

# Step 2: Copy current directory into deps/<current_dir_name>
copy:
	@set -e; \
	for plugin in $(PLUGINS); do \
		echo "Copying files of $$plugin..."; \
		mkdir -p $(RABBITMQ_PLUGIN_DIR)/$$plugin; \
		rm -rf $(RABBITMQ_PLUGIN_DIR)/$$plugin/*; \
		rsync -av --ignore-missing-args ./$$plugin/ $(RABBITMQ_PLUGIN_DIR)/$$plugin/; \
	done

build: deps
	@echo "Building RabbitMQ plugins..."
	@rm -rf plugins
	@mkdir -p plugins
	@set -e; \
	for plugin in $(PLUGINS); do \
		echo "Creating $$plugin dist..."; \
		make -C $(RABBITMQ_PLUGIN_DIR)/$$plugin dist; \
		cp -r $(RABBITMQ_PLUGIN_DIR)/$$plugin/plugins/* plugins/; \
	done
	$(call make_docker)

run:
	docker compose -p smq_rabbit_$(subst .,_,$(RABBITMQ_VERSION)) -f docker/docker-compose.yaml up

clean:
	rm -rf deps
	rm -rf plugins
	rm -rf rabbitmq-server

clean-smq-auth:
	rm -rf rabbitmq-server/deps/smq-auth
