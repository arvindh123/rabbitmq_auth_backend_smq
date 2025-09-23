#!/bin/bash

# Generate CA private key
openssl genrsa -out ca.key 2048

# Generate CA certificate
openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 \
  -out ca.crt \
  -subj "/C=XX/ST=YY/L=City/O=Organization/OU=OrganizationUnit/CN=TestCA"


# Private key
openssl genrsa -out server.key 2048

# CSR (Certificate Signing Request)
openssl req -new -key server.key -out server.csr \
  -subj "/C=XX/ST=YY/L=City/O=Organization/OU=OrganizationUnit/CN=localhost"

# Sign with CA
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out server.crt -days 365 -sha256


