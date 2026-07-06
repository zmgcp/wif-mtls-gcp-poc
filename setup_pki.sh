#!/usr/bin/env bash
# ==============================================================================
# setup_pki.sh - Mock PKI Setup for GCP WIF mTLS X.509 Authentication Demo
# ==============================================================================
# This script uses OpenSSL to generate a self-signed Root Certificate Authority
# (CA), a server certificate for the custom broker (for local mTLS testing),
# and an authenticated client certificate signed by the Root CA with CN="client-01".
# ==============================================================================

set -euo pipefail

# Define absolute paths and variables
WORKSPACE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BROKER_DIR="${WORKSPACE_DIR}/broker"
CERTS_DIR="${WORKSPACE_DIR}"

# Ensure broker directory exists
mkdir -p "${BROKER_DIR}"

echo "=============================================================================="
echo "Starting Mock PKI Generation in: ${CERTS_DIR}"
echo "=============================================================================="

# 1. Generate Root CA Private Key and Self-Signed Certificate
echo "[Step 1/3] Generating Root CA (rootCA.key, rootCA.pem)..."
openssl req -x509 -new -nodes \
    -keyout "${CERTS_DIR}/rootCA.key" \
    -sha256 -days 3650 \
    -out "${CERTS_DIR}/rootCA.pem" \
    -subj "/C=US/ST=California/L=Mountain View/O=GCP DevOps Demo/OU=Security/CN=Demo Root CA"

# Secure Root CA private key per Mandatory Secure Web Skills (Least Privilege / Path Security)
chmod 600 "${CERTS_DIR}/rootCA.key"
chmod 644 "${CERTS_DIR}/rootCA.pem"

# 2. Generate Server Certificate for Broker (for local Gunicorn mTLS testing)
echo "[Step 2/3] Generating Server Certificate for Broker (server.key, server.pem)..."
openssl req -new -nodes \
    -keyout "${CERTS_DIR}/server.key" \
    -out "${CERTS_DIR}/server.csr" \
    -subj "/C=US/ST=California/L=Mountain View/O=GCP DevOps Demo/OU=Broker/CN=localhost"

# Create X.509 V3 extension config for server authentication (DNS & IP SANs)
cat <<EOF > "${CERTS_DIR}/server_ext.cnf"
basicConstraints=CA:FALSE
subjectAltName=DNS:localhost,IP:127.0.0.1,DNS:broker
extendedKeyUsage=serverAuth
EOF

openssl x509 -req -in "${CERTS_DIR}/server.csr" \
    -CA "${CERTS_DIR}/rootCA.pem" \
    -CAkey "${CERTS_DIR}/rootCA.key" \
    -CAcreateserial \
    -out "${CERTS_DIR}/server.pem" \
    -days 365 -sha256 \
    -extfile "${CERTS_DIR}/server_ext.cnf"

chmod 600 "${CERTS_DIR}/server.key"
chmod 644 "${CERTS_DIR}/server.pem"
rm -f "${CERTS_DIR}/server.csr" "${CERTS_DIR}/server_ext.cnf"

# 3. Generate Client Private Key and Certificate Signing Request (CSR) with CN="client-01"
echo "[Step 3/3] Generating Client Certificate with CN='client-01' (client.key, client.pem)..."
openssl req -new -nodes \
    -keyout "${CERTS_DIR}/client.key" \
    -out "${CERTS_DIR}/client.csr" \
    -subj "/C=US/ST=California/L=Mountain View/O=GCP DevOps Demo/OU=Client/CN=client-01"

# Create X.509 V3 extension config for client authentication
cat <<EOF > "${CERTS_DIR}/client_ext.cnf"
basicConstraints=CA:FALSE
extendedKeyUsage=clientAuth
EOF

openssl x509 -req -in "${CERTS_DIR}/client.csr" \
    -CA "${CERTS_DIR}/rootCA.pem" \
    -CAkey "${CERTS_DIR}/rootCA.key" \
    -CAcreateserial \
    -out "${CERTS_DIR}/client.pem" \
    -days 365 -sha256 \
    -extfile "${CERTS_DIR}/client_ext.cnf"

chmod 600 "${CERTS_DIR}/client.key"
chmod 644 "${CERTS_DIR}/client.pem"
rm -f "${CERTS_DIR}/client.csr" "${CERTS_DIR}/client_ext.cnf" "${CERTS_DIR}/rootCA.srl"

# Copy Root CA and server certs to broker directory for container packaging & local dev
echo "Copying rootCA.pem, server.pem, and server.key to ${BROKER_DIR}..."
cp "${CERTS_DIR}/rootCA.pem" "${BROKER_DIR}/rootCA.pem"
cp "${CERTS_DIR}/server.pem" "${BROKER_DIR}/server.pem"
cp "${CERTS_DIR}/server.key" "${BROKER_DIR}/server.key"

echo "=============================================================================="
echo "PKI Setup Successfully Completed!"
echo "Generated files in ${CERTS_DIR}:"
echo "  - Root CA:     rootCA.pem, rootCA.key"
echo "  - Broker Cert: server.pem, server.key"
echo "  - Client Cert: client.pem, client.key (Subject CN: client-01)"
echo "=============================================================================="
