#!/usr/bin/env python
from common import SupermqClient

HOST = "localhost"
USERNAME = "admin"
PASSWORD = "secret"
def internal_non_tls():
    PORT = "5673"
    SupermqClient(host=HOST, port=PORT, username=USERNAME, password=PASSWORD).test_connection()

def internal_tls():
    PORT = "5670"
    SupermqClient(host=HOST, port=PORT, username=USERNAME, password=PASSWORD, ca_cert="docker/certs/ca.crt").test_connection()

def internal_mtls():
    PORT = "5670"
    SupermqClient(host=HOST, port=PORT, username=USERNAME, password=PASSWORD,ca_cert="docker/certs/ca.crt", client_cert="docker/certs/client.crt", client_key="docker/certs/client.key").test_connection()

if __name__ == "__main__":
    internal_non_tls()
    print("======================================")
    internal_tls()
    print("======================================")
    internal_mtls()
