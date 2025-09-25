FROM rabbitmq:4.1.4-management

# Install envsubst
RUN apt-get update && \
    apt-get install -y gettext-base && \
    rm -rf /var/lib/apt/lists/*

# Copy your built plugins
COPY ./plugins /opt/rabbitmq/plugins


RUN rabbitmq-plugins enable --offline rabbitmq_auth_backend_supermq

RUN rabbitmq-plugins enable --offline rabbitmq_auth_mechanism_supermq_mtls
