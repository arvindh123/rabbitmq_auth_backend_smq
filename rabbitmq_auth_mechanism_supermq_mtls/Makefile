PROJECT = rabbitmq_auth_mechanism_supermq_mtls
PROJECT_DESCRIPTION = RabbitMQ Auth Mechanism for SuperMQ SSL
PROJECT_MOD = rabbitmq_auth_mechanism_supermq_mtls_app
RABBITMQ_VERSION := 4.1.4
RABBITMQ_REPO    := https://github.com/rabbitmq/rabbitmq-server

DEPS = rabbit_common rabbit amqp_client
TEST_DEPS = rabbitmq_ct_helpers rabbitmq_ct_client_helpers

DEP_EARLY_PLUGINS = rabbit_common/mk/rabbitmq-early-plugin.mk
DEP_PLUGINS = rabbit_common/mk/rabbitmq-plugin.mk

# FIXME: Use erlang.mk patched for RabbitMQ, while waiting for PRs to be
# reviewed and merged.

ERLANG_MK_REPO = https://github.com/rabbitmq/erlang.mk.git
ERLANG_MK_COMMIT = rabbitmq-tmp

include ../../rabbitmq-components.mk
include ../../erlang.mk
