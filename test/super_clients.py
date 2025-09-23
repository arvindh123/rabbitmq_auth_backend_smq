#!/usr/bin/env python
from common import SupermqClient

HOST = "localhost"
SUPERMQ_CLIENT_ID="5b6fcf9d-6f98-4dc7-b400-aedb6645e0ca"
SUPERMQ_CLIENT_KEY="085cd178-dbb9-429f-891d-013ed061a80b"

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
