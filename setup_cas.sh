#!/usr/bin/env bash
# ==============================================================================
# setup_cas.sh - Google Cloud Certificate Authority Service (CAS) Setup
# ==============================================================================
# This script provisions a PKI hierarchy using Google Cloud CAS for GA WIF X.509:
# 1. Enables privateca.googleapis.com API.
# 2. Creates a DevOps-tier CA Pool (optimized for testing/ephemeral certs).
# 3. Creates and enables a Root CA in GCP CAS.
# 4. Exports the Root CA public certificate to rootCA.pem and formats trust_store.yaml.
# 5. Generates a client RSA private key locally and submits a CSR to CAS.
# 6. Outputs the CAS-signed client certificate (client.pem).
# ==============================================================================

set -euo pipefail

PROJECT_ID="${1:-bionic-mercury-498422-e9}"
REGION="${2:-us-central1}"
CA_POOL_NAME="demo-mtls-ca-pool"
ROOT_CA_NAME="demo-mtls-root-ca"
CLIENT_CERT_NAME="client-01-cert"

echo "=============================================================================="
echo "GCP Certificate Authority Service (CAS) PKI Setup (GA WIF X.509)"
echo "=============================================================================="
echo "  Project ID: ${PROJECT_ID}"
echo "  Region:     ${REGION}"
echo "  CA Pool:    ${CA_POOL_NAME} (Tier: DEVOPS)"
echo "  Root CA:    ${ROOT_CA_NAME}"
echo "=============================================================================="

# 1. Enable Certificate Authority Service API
echo "[Step 1/6] Enabling privateca.googleapis.com API..."
gcloud services enable privateca.googleapis.com --project="${PROJECT_ID}" --quiet

# 2. Create CA Pool
echo "[Step 2/6] Creating CAS CA Pool '${CA_POOL_NAME}' (Tier: DEVOPS)..."
if ! gcloud privateca pools describe "${CA_POOL_NAME}" --location="${REGION}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
    gcloud privateca pools create "${CA_POOL_NAME}" \
        --location="${REGION}" \
        --tier="DEVOPS" \
        --project="${PROJECT_ID}" \
        --quiet
    echo "CA Pool created successfully."
else
    echo "CA Pool '${CA_POOL_NAME}' already exists."
fi

# 3. Create Root CA
echo "[Step 3/6] Creating and enabling Root CA '${ROOT_CA_NAME}'..."
if ! gcloud privateca roots describe "${ROOT_CA_NAME}" --pool="${CA_POOL_NAME}" --location="${REGION}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
    gcloud privateca roots create "${ROOT_CA_NAME}" \
        --pool="${CA_POOL_NAME}" \
        --location="${REGION}" \
        --subject="CN=GCP CAS WIF Demo Root CA,O=Google Cloud Demo" \
        --key-algorithm="rsa-pkcs1-2048-sha256" \
        --max-chain-length=1 \
        --project="${PROJECT_ID}" \
        --quiet
    echo "Root CA created successfully."
else
    echo "Root CA '${ROOT_CA_NAME}' already exists."
fi

# Ensure Root CA is enabled
gcloud privateca roots enable "${ROOT_CA_NAME}" \
    --pool="${CA_POOL_NAME}" \
    --location="${REGION}" \
    --project="${PROJECT_ID}" \
    --quiet 2>/dev/null || true

# 4. Export Root CA Certificate & Format trust_store.yaml
echo "[Step 4/6] Exporting Root CA certificate and formatting trust_store.yaml..."
gcloud privateca roots describe "${ROOT_CA_NAME}" \
    --pool="${CA_POOL_NAME}" \
    --location="${REGION}" \
    --project="${PROJECT_ID}" \
    --format="value(pemCaCertificates[0])" > rootCA.pem

# Format rootCA.pem with 6-space indentation for YAML trust store specification
ROOT_CERT_INDENTED=$(sed 's/^/      /' rootCA.pem)
cat <<EOF > trust_store.yaml
trustStore:
  trustAnchors:
  - pemCertificate: |
${ROOT_CERT_INDENTED}
EOF

echo "Exported Root CA to rootCA.pem and generated trust_store.yaml."

# 5. Generate Client Key and CSR Locally
echo "[Step 5/6] Generating local client RSA private key and Certificate Signing Request (CSR)..."
openssl req -new -newkey rsa:2048 -nodes \
    -keyout client.key \
    -out client.csr \
    -subj "/CN=client-01" 2>/dev/null

chmod 600 client.key
echo "Generated client.key (600 permissions) and client.csr."

# 6. Submit CSR to CAS for Signing
echo "[Step 6/6] Submitting CSR to GCP CAS to issue signed client certificate..."
gcloud privateca certificates delete "${CLIENT_CERT_NAME}" \
    --issuer-pool="${CA_POOL_NAME}" \
    --location="${REGION}" \
    --project="${PROJECT_ID}" \
    --quiet 2>/dev/null || true

gcloud privateca certificates create "${CLIENT_CERT_NAME}" \
    --issuer-pool="${CA_POOL_NAME}" \
    --issuer-location="${REGION}" \
    --csr="client.csr" \
    --cert-output-file="client.pem" \
    --validity="P30D" \
    --project="${PROJECT_ID}" \
    --quiet

rm -f client.csr
echo "=============================================================================="
echo "GCP CAS PKI Setup Complete!"
echo "=============================================================================="
echo "  Root CA Cert:       $(pwd)/rootCA.pem"
echo "  WIF Trust Store:    $(pwd)/trust_store.yaml"
echo "  Client Private Key: $(pwd)/client.key"
echo "  Client Certificate: $(pwd)/client.pem (Signed by GCP CAS)"
echo "=============================================================================="
