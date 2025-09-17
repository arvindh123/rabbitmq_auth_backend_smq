FROM rabbitmq:4.1.4-management

# Copy your built plugins
COPY ./plugins /opt/rabbitmq/plugins


# Enable your plugin (replace with your actual plugin name)
RUN rabbitmq-plugins enable --offline rabbitmq_auth_backend_smq
