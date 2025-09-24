import ssl
import traceback
import pika
from pika.compat import as_bytes
from pika.credentials import  PlainCredentials, ExternalCredentials
import paho.mqtt.client as mqtt
import time

class SupermqmTLSCredentials(ExternalCredentials):
    """Custom SASL mechanism for SUPERMQ."""
    TYPE = "SUPERMQ_MTLS"
    def __init__(self):
        super().__init__()
    def response_for(self, start):
        """Validate that this type of authentication is supported

        :param spec.Connection.Start start: Connection.Start method
        :rtype: tuple(str or None, str or None)

        """
        """Return SUPERMQ instead of EXTERNAL if broker supports it."""
        if as_bytes(SupermqmTLSCredentials.TYPE) not in as_bytes(start.mechanisms).split():
            return None, None
        return self.TYPE, b''

class SupermqCredentialsPlus(PlainCredentials):
    """Custom SASL mechanism for SUPERMQ."""
    TYPE = "SUPERMQ_MTLS"
    def __init__(self, username, password, erase_on_connect=False):
        super().__init__(username, password, erase_on_connect)

    def response_for(self, start):
        """Validate that this type of authentication is supported

        :param spec.Connection.Start start: Connection.Start method
        :rtype: tuple(str|None, str|None)

        """
        if as_bytes(SupermqCredentialsPlus.TYPE) not in\
                as_bytes(start.mechanisms).split():
            return None, None
        return (
            SupermqCredentialsPlus.TYPE,
            b'\0' + as_bytes(self.username) + b'\0' + as_bytes(self.password))



class SupermqClient:
    def __init__(self, host="localhost", port=5670,
                 username=None, password=None,
                 ca_cert=None, client_cert=None, client_key=None):

        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.ca_cert = ca_cert
        self.client_cert = client_cert
        self.client_key = client_key
        self.connection = None
        self.channel = None
        self.SaslType = None

    def _create_ssl_context(self):
        """Builds SSL context based on provided certs."""
        if not self.ca_cert:
            return None  # No TLS

        context = ssl.create_default_context(cafile=self.ca_cert)

        # If client cert & key provided → mTLS
        if self.client_cert and self.client_key:
            context.load_cert_chain(self.client_cert, self.client_key)
            print("🔐 Using mTLS (client + server certs).")
        else:
            print("🔐 Using TLS (server cert only).")

        context.verify_mode = ssl.CERT_REQUIRED
        return context

    def _create_credentials(self):
        if self.client_cert and  self.client_key:
            self.SaslType="SUPERMQ_MTLS"
            return SupermqmTLSCredentials()
        if self.username and self.password:
            self.SaslType="PLAIN"
            return PlainCredentials(
                username=self.username,
                password=self.password,
            )


    def _build_conn_params(self):
        ssl_context = self._create_ssl_context()
        credentials = self._create_credentials()

        if ssl_context:
            ssl_options = pika.SSLOptions(ssl_context, self.host)
            return pika.ConnectionParameters(
                host=self.host,
                port=self.port,
                ssl_options=ssl_options,
                credentials=credentials,
            )
        else:
            print("⚠️ Connecting without TLS.")
            return pika.ConnectionParameters(
                host=self.host,
                port=self.port,
                credentials=credentials,
            )

    def connect(self):
        try:
            conn_params = self._build_conn_params()
            self.connection = pika.BlockingConnection(conn_params)
            self.channel = self.connection.channel()
            print(
                f"✅ Successfully connected to RabbitMQ "
                f"Host={self.host}, Port={self.port}, SASL={self.SaslType} "
                f"User={self.username}, Pass={'***' if self.password else None}, "
                f"CA={self.ca_cert}, ClientCert={self.client_cert}, ClientCert={self.client_key}, "
            )
        except pika.exceptions.AMQPConnectionError as e:
            traceback.print_exc()
            print(f"❌ Failed to connect to RabbitMQ: {e}")

    def publish(self, queue_name, message):
        if not self.channel:
            raise RuntimeError("Not connected. Call connect() first.")
        self.channel.queue_declare(queue=queue_name)
        self.channel.basic_publish(exchange='', routing_key=queue_name, body=message)
        print(f"📤 Sent message to queue '{queue_name}': {message}")

    def close(self):
        if self.connection:
            self.connection.close()
            print("🔒 Connection closed.")

    def test_connection(self):
        """Runs a simple test: connect → declare queue → publish → close."""
        try:
            self.connect()
            connection = self.connection
            channel = self.connection.channel()

            channel.queue_declare(queue='hello')
            channel.basic_publish(exchange='', routing_key='hello', body='Hello World!')
            print("📤 Test message 'Hello World!' sent to queue 'hello'.")

            connection.close()
            print("🔒 Test connection closed.")
        except Exception as e:
            traceback.print_exc()
            print(f"❌ Test connection failed: {e}")


class SupermqMQTTClient:
    """
    MQTT client for SuperMQ supporting:
      - Non-TLS
      - TLS
      - mTLS (mutual TLS)
    """
    def __init__(self, host, port, username=None, password=None,
                 ca_cert=None, client_cert=None, client_key=None,test_topic="hello"):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.ca_cert = ca_cert
        self.client_cert = client_cert
        self.client_key = client_key
        self.client = mqtt.Client()
        self.connType = ""


        if self.username and self.password:
            self.client.username_pw_set(username, password)

        if self.ca_cert:
            if self.client_cert and self.client_key:
                # mTLS
                self.client.tls_set(ca_certs=self.ca_cert,
                                    certfile=self.client_cert,
                                    keyfile=self.client_key,
                                    cert_reqs=ssl.CERT_REQUIRED,
                                    tls_version=ssl.PROTOCOL_TLS_CLIENT)
                self.connType = "mTLS"
                print("🔐 Using mTLS (client + server certificates).")
            else:
                # TLS only
                self.client.tls_set(ca_certs=self.ca_cert,
                                    cert_reqs=ssl.CERT_REQUIRED,
                                    tls_version=ssl.PROTOCOL_TLS_CLIENT)
                self.connType = "TLS"
                print("🔐 Using TLS (server certificate only).")
        else:
            self.connType = "without TLS"
            print("⚠️ Connecting without TLS.")

    def connect(self):
        """Connect to MQTT broker."""
        try:
            self.client.connect(self.host, self.port)
            print(f"✅ Connected to MQTT broker at {self.host}:{self.port}")
        except Exception as e:
            traceback.print_exc()
            print(f"❌ Connection failed: {e}")

    def publish(self, topic, message):
        """Publish a message to a topic."""
        result = self.client.publish(topic, message)
        status = result[0]
        if status == 0:
            print(f"📤 Sent message to topic '{topic}': {message}")
        else:
            print(f"❌ Failed to send message to topic {topic}")



    def disconnect(self):
        """Disconnect from MQTT broker."""
        self.client.disconnect()
        print("🔒 Disconnected from MQTT broker.")

    def test_publish(self, topic, message="Hello World!"):
        """Test connection by connecting, publishing, and disconnecting."""
        message = f"{message} from {self.connType}"
        try:
            self.client.connect(self.host, self.port)
            self.client.loop_start()  # ensures publish+disconnect actually run
            info =self.client.publish(topic,message  )
            info.wait_for_publish()
            print(f"✅ Published to '{topic}': {message}")

            # Optional: give broker a moment before disconnect
            time.sleep(0.5)

            self.client.loop_stop()
            self.client.disconnect()
        except Exception as e:
            traceback.print_exc()
            print(f"❌ Test publish failed: {e}")

    def test_subscribe(self, topic):
        """Test subscribing to a topic."""

        def on_connect(client, userdata, flags, rc):
            if rc == 0:
                print("✅ Connected successfully, subscribing...")
                client.subscribe(topic)
            else:
                print(f"❌ Connection failed with code {rc}")

        def on_message(client, userdata, msg):
            print(f"📥 Received message at {self.connType}: {msg.payload.decode()} on topic {msg.topic}")
        def on_subscribe(client, userdata, mid, granted_qos):
            print(f"📡 Subscribed! mid={mid}, QoS={granted_qos}")

        self.client.on_connect = on_connect
        self.client.on_message = on_message
        self.client.on_subscribe = on_subscribe

        try:
            self.client.connect(self.host, self.port)
            print(f"🔗 Subscribing to {topic} on {self.host}:{self.port}")
            self.client.loop_start()  # ✅ start loop to receive messages
        except Exception as e:
            print(f"❌ Subscribe failed: {e}")

class SupermqMQTTWSClient(SupermqMQTTClient):
    def __init__(self, host, port, username=None, password=None,
                 ca_cert=None, client_cert=None, client_key=None,
                 test_topic="hello", ws_path="/mqtt"):
        super().__init__(host, port, username, password,
                         ca_cert, client_cert, client_key,
                         test_topic)
        self.client = mqtt.Client(transport="websockets")
        self.client.ws_set_options(path=ws_path)

        if self.username and self.password:
            self.client.username_pw_set(username, password)

        if self.ca_cert:
            if self.client_cert and self.client_key:
                # mTLS
                self.client.tls_set(ca_certs=self.ca_cert,
                                    certfile=self.client_cert,
                                    keyfile=self.client_key,
                                    cert_reqs=ssl.CERT_REQUIRED,
                                    tls_version=ssl.PROTOCOL_TLS_CLIENT)
                self.connType = "mTLS"
                print("🔐 Using mTLS (client + server certificates).")
            else:
                # TLS only
                self.client.tls_set(ca_certs=self.ca_cert,
                                    cert_reqs=ssl.CERT_REQUIRED,
                                    tls_version=ssl.PROTOCOL_TLS_CLIENT)
                self.connType = "TLS"
                print("🔐 Using TLS (server certificate only).")
        else:
            self.connType = "without TLS"
            print("⚠️ Connecting without TLS.")
        self.connType += " (WebSocket)"

        print(f"🌐 Using MQTT over WebSocket at path {ws_path} {self.username} {self.password } {self.host} {self.port}")


if __name__ == "__main__":

    # Example: mTLS
    # client = SupermqClient(
    #     host="localhost",
    #     port=5670,
    #     username=None,   # or "guest"
    #     password=None,   # or "guest"
    #     ca_cert="docker/certs/ca.crt",          # Optional
    #     client_cert="docker/certs/client.crt",  # Optional
    #     client_key="docker/certs/client.key"    # Optional
    # )

    # client.test_connection()
    import os
    print("This is a library for testing")
    os.exit(1)
    pass

