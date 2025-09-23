#!/bin/bash
set -e

usage() {
    echo "Usage:"
    echo "  $0 --internal <username>"
    echo "  $0 --supermq-client <client_id>"
    echo
    echo "Options:"
    echo "  --internal              Generate cert with CN=internal, filenames = client.*"
    echo "  --supermq-client <id>   Generate cert for supermq client id, filenames = supermq-client.*"
    exit 1
}

if [ $# -eq 0 ]; then
    usage
fi

MODE=""
CN=""
PREFIX=""

case "$1" in
    --internal)
        if [ -z "$2" ]; then
            echo "❌ Missing argument: RabbitMQ Username"
            usage
        fi
        MODE="internal"
        CN="$2"
        PREFIX="client"
        ;;
    --supermq-client)
        if [ -z "$2" ]; then
            echo "❌ Missing argument: Supermq Client ID"
            usage
        fi
        MODE="supermq"
        CN="$2"
        PREFIX="supermq-client"
        ;;
    *)
        echo "❌ Unknown option: $1"
        usage
        ;;
esac

# Generate private key
openssl genrsa -out "${PREFIX}.key" 2048

# Generate CSR
openssl req -new -key "${PREFIX}.key" -out "${PREFIX}.csr" \
  -subj "/C=XX/ST=YY/L=City/O=RabbitMQ/OU=Client/CN=${CN}"

# Sign CSR with CA
openssl x509 -req -in "${PREFIX}.csr" -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out "${PREFIX}.crt" -days 365 -sha256

echo "✅ Certificate generated: ${PREFIX}.crt (CN=${CN})"
