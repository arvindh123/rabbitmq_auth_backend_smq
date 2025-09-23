FROM rabbitmq:4.1.4-management

# Copy your built plugins
COPY ./plugins /opt/rabbitmq/plugins


RUN rabbitmq-plugins enable --offline rabbitmq_auth_backend_supermq

RUN rabbitmq-plugins enable --offline rabbitmq_auth_mechanism_supermq_mtls
