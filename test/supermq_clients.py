#!/usr/bin/env python
from common import SupermqClient

HOST = "localhost"
SUPERMQ_CLIENT_ID="<SUPERMQ_CLIENT_ID>" ## Replace here with SuperMQ Client ID
SUPERMQ_CLIENT_KEY="<SUPERMQ_CLIENT_KEY>" ## Replace here with SuperMQ Client Key

USERNAME = SUPERMQ_CLIENT_ID
PASSWORD = SUPERMQ_CLIENT_KEY

def supermq_client_non_tls():
    PORT = "5672"
    SupermqClient(host=HOST, port=PORT, username=USERNAME, password=PASSWORD).test_connection()

def supermq_client_tls():
    PORT = "5671"
    SupermqClient(host=HOST, port=PORT, username=USERNAME, password=PASSWORD, ca_cert="docker/certs/ca.crt").test_connection()

def supermq_client_mtls():
    PORT = "5671"
    SupermqClient(host=HOST, port=PORT, username=USERNAME, password=PASSWORD,ca_cert="docker/certs/ca.crt", client_cert="docker/certs/supermq-client.crt", client_key="docker/certs/supermq-client.key").test_connection()

if __name__ == "__main__":
    supermq_client_non_tls()
    print("======================================")
    supermq_client_tls()
    print("======================================")
    supermq_client_mtls()
