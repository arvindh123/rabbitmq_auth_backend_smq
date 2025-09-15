PROJECT = rabbitmq_auth_backend_smq
PROJECT_DESCRIPTION = RabbitMQ SMQ Authentication Backend
PROJECT_MOD = rabbitmq_auth_backend_smq
RABBITMQ_VERSION = v4.1.4
RABBITMQ_REPO = https://github.com/rabbitmq/rabbitmq-server.git

define PROJECT_ENV
[
	    {http_method,   	 get},
	    {request_timeout,    15000},
	    {connection_timeout, 15000},
	    {user_path,     "http://localhost:8000/auth/user"},
	    {vhost_path,    "http://localhost:8000/auth/vhost"},
	    {resource_path, "http://localhost:8000/auth/resource"},
	    {topic_path,    "http://localhost:8000/auth/topic"}
	  ]
endef


define PROJECT_APP_EXTRA_KEYS
	{broker_version_requirements, []}
endef


# RABBITMQ_INTERNAL_DEPS = rabbit rabbitmq_cli amqp10_common rabbitmq_prelaunch
# RABBITMQ_DEPS = rabbit_common  amqp_client ${RABBITMQ_INTERNAL_DEPS}

# DEPS = ${RABBITMQ_DEPS} smq_auth
DEPS = rabbit_common  amqp_client smq_auth
TEST_DEPS = rabbitmq_ct_helpers rabbitmq_ct_client_helpers

# # Define a function to create deps from the same repo
# define dep_rabbitmq_template
# dep_$(1) = git-subfolder ${RABBITMQ_REPO} ${RABBITMQ_VERSION} deps/$(1)
# endef
# # Apply it to all RabbitMQ dependencies
# $(foreach comp,$(RABBITMQ_DEPS),$(eval $(call dep_rabbitmq_template,$(comp))))



dep_rabbit_common = git-subfolder ${RABBITMQ_REPO} ${RABBITMQ_VERSION} deps/rabbit_common
dep_amqp_client = git-subfolder ${RABBITMQ_REPO} ${RABBITMQ_VERSION} deps/amqp_client
dep_smq_auth = git https://github.com/arvindh123/smq_auth.git master

LOCAL_DEPS = ssl inets crypto public_key

DEP_EARLY_PLUGINS = rabbit_common/mk/rabbitmq-early-plugin.mk
DEP_PLUGINS = rabbit_common/mk/rabbitmq-plugin.mk

# FIXME: Use erlang.mk patched for RabbitMQ, while waiting for PRs to be
# reviewed and merged.

ERLANG_MK_REPO = https://github.com/rabbitmq/erlang.mk.git
ERLANG_MK_COMMIT = rabbitmq-tmp


ERLC_OPTS +=  +warn_unused_vars

# include rabbitmq-components.mk
include erlang.mk


.PHONY: fetch-rabbit

# Target: fetch just deps/rabbit
fetch-rabbit:
	@echo "Fetching deps/rabbit from RabbitMQ Server (${RABBITMQ_VERSION})..."
	@rm -rf deps/rabbit
	@git clone --depth 1 --branch ${RABBITMQ_VERSION} ${RABBITMQ_REPO} tmp-rabbit
	@mkdir -p deps
	@mv tmp-rabbit/deps/rabbit deps/
	@rm -rf tmp-rabbit
	@echo "✅ deps/rabbit cloned successfully."


fetch-deps: fetch-rabbit


# Disable RabbitMQ CLI-related tasks to avoid errors
NO_CLI_TARGETS = install-cli-scripts install-cli-escripts dialyze

# Override CLI targets to noop
$(NO_CLI_TARGETS):
	@echo "Skipping RabbitMQ CLI target $@"

