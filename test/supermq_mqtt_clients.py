#!/usr/bin/env python
from common import SupermqMQTTClient
import time
HOST = "localhost"
SUPERMQ_CLIENT_ID="5b6fcf9d-6f98-4dc7-b400-aedb6645e0ca" ## Replace here with SuperMQ Client ID
SUPERMQ_CLIENT_KEY="085cd178-dbb9-429f-891d-013ed061a80b" ## Replace here with SuperMQ Client Key
SUPERMQ_DOMAIN_ID="abbe43fa-fb9e-40b1-acaa-0fe1b33cd90f" ## Replace here with SuperMQ Domain ID
SUPERMQ_CHANNEL_ID="2fd755bf-aba7-4e2d-818f-158727abae64" ## Replace here with SuperMQ Channel ID
USERNAME = SUPERMQ_CLIENT_ID
PASSWORD = SUPERMQ_CLIENT_KEY

topic = f"m/{SUPERMQ_DOMAIN_ID}/c/{SUPERMQ_CHANNEL_ID}/hello"
def supermq_client_non_tls_sub():
    PORT = 1883
    SupermqMQTTClient(host=HOST, port=PORT, username=USERNAME, password=PASSWORD).test_subscribe(topic)

def supermq_client_tls_sub():
    PORT = 8883
    SupermqMQTTClient(host=HOST, port=PORT, username=USERNAME, password=PASSWORD, ca_cert="docker/certs/ca.crt").test_subscribe(topic)

def supermq_client_mtls_sub():
    PORT = 8883
    SupermqMQTTClient(host=HOST, port=PORT, ca_cert="docker/certs/ca.crt", client_cert="docker/certs/supermq-client.crt", client_key="docker/certs/supermq-client.key").test_subscribe(topic)



def supermq_client_non_tls_pub():
    PORT = 1883
    SupermqMQTTClient(host=HOST, port=PORT, username=USERNAME, password=PASSWORD).test_publish(topic)

def supermq_client_tls_pub():
    PORT = 8883
    SupermqMQTTClient(host=HOST, port=PORT, username=USERNAME, password=PASSWORD, ca_cert="docker/certs/ca.crt").test_publish(topic)

def supermq_client_mtls_pub():
    PORT = 8883
    SupermqMQTTClient(host=HOST, port=PORT, ca_cert="docker/certs/ca.crt", client_cert="docker/certs/supermq-client.crt", client_key="docker/certs/supermq-client.key").test_publish(topic)

def supermq_client_mtls_pub_invalid_certs():
    PORT = 8883
    SupermqMQTTClient(host=HOST, port=PORT, ca_cert="docker/certs/ca.crt", client_cert="docker/certs/client.crt", client_key="docker/certs/client.key").test_publish(topic)

if __name__ == "__main__":
    supermq_client_non_tls_sub()
    print("======================================")
    supermq_client_tls_sub()
    print("======================================")
    supermq_client_mtls_sub()
    print("======================================")
    time.sleep(1)
    supermq_client_non_tls_pub()
    print("======================================")
    supermq_client_tls_pub()
    print("======================================")
    supermq_client_mtls_pub()
    print("======================================")
    print("Connecting with internal client certificates")
    supermq_client_mtls_pub_invalid_certs()
    time.sleep(1)
