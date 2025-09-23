import ssl
import traceback
import pika
from pika.compat import as_bytes
from pika.credentials import  PlainCredentials, ExternalCredentials

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
