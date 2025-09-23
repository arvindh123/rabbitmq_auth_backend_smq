# genCaAndServerCerts.sh 

This script generates a **Certificate Authority (CA)** and a **Server certificate/key pair** signed by that CA.
It is useful when you need to create a simple PKI setup for testing or internal use.

---

## Usage

Run the script directly:

```bash
./genCaAndServerCerts.sh
```

The script will automatically:

1. Generate a **CA private key** (`ca.key`)
2. Generate a **self-signed CA certificate** (`ca.crt`) valid for 10 years
3. Generate a **server private key** (`server.key`)
4. Generate a **server CSR** (`server.csr`)
5. Sign the server CSR with the CA to produce a **server certificate** (`server.crt`) valid for 1 year

---

## Files Generated

After running, the following files will be created in the current directory:

* `ca.key` → CA private key
* `ca.crt` → Self-signed CA certificate
* `server.key` → Server private key
* `server.csr` → Server certificate signing request
* `server.crt` → Server certificate signed by CA

---

## Example Run

```bash
$ ./genCaAndServerCerts.sh
Generating RSA private key, 2048 bit long modulus
...+++++
..................+++++
writing new private key to 'ca.key'
-----
Generating RSA private key, 2048 bit long modulus
...........+++++
....................+++++
writing new private key to 'server.key'
-----
Signature ok
subject=C = XX, ST = YY, L = City, O = Organization, OU = OrganizationUnit, CN = localhost
Getting CA Private Key
```

---

# genClientCerts.sh

A helper script to generate TLS/mTLS client certificates for RabbitMQ connections.

---

## Usage

```bash
./genClientCerts.sh --internal
./genClientCerts.sh --supermq-client <client_id>
```

### Options

* `--internal`
  Generate certificate with **CN=internal**.
  Output filenames:

  * `client.key`
  * `client.csr`
  * `client.crt`

* `--supermq-client <id>`
  Generate certificate for a **SuperMQ client ID**.
  Output filenames:

  * `supermq-client.key`
  * `supermq-client.csr`
  * `supermq-client.crt`

---

## Examples

### Internal certificate

```bash
./genClientCerts.sh --internal
```

**Output:**

```
Certificate request self-signature ok
subject=C = IN, ST = TN, L = Chennai, O = RabbitMQ, OU = Client, CN = internal
✅ Certificate generated: client.crt (CN=internal)
```

### Internal certificate with custom CN

```bash
./genClientCerts.sh --internal admin
```

**Output:**

```
Certificate request self-signature ok
subject=C = XX, ST = YY, L = City, O = RabbitMQ, OU = Client, CN = admin
✅ Certificate generated: client.crt (CN=admin)
```

### SuperMQ client certificate

```bash
./genClientCerts.sh --supermq-client 5b6fcf9d-6f98-4dc7-b400-aedb6645e0ca
```

**Output:**

```
Certificate request self-signature ok
subject=C = XX, ST = YY, L = City, O = RabbitMQ, OU = Client, CN = 5b6fcf9d-6f98-4dc7-b400-aedb6645e0ca
✅ Certificate generated: supermq-client.crt (CN=5b6fcf9d-6f98-4dc7-b400-aedb6645e0ca)
```

---

## Notes

* Requires an existing **CA certificate** (`ca.crt`) and **CA private key** (`ca.key`) in the current directory.
* Certificates are valid for **365 days** by default.
* Adjust the DN fields (`C`, `ST`, `L`, `O`, `OU`) inside the script if needed.
