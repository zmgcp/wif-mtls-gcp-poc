#!/usr/bin/env bash
# ==============================================================================
# cleanup_cas.sh - Safely Disables and Deletes GCP CAS Certificate Authorities
# ==============================================================================
# Per user requirement, removes generated CAs and CA pools after testing to
# prevent ongoing cloud charges or lingering resources.
# ==============================================================================

set -euo pipefail

PROJECT_ID="${1:-bionic-mercury-498422-e9}"
REGION="${2:-us-central1}"
CA_POOL_NAME="demo-mtls-ca-pool"
ROOT_CA_NAME="demo-mtls-root-ca"

echo "=============================================================================="
echo "GCP Certificate Authority Service (CAS) Cleanup"
echo "=============================================================================="
echo "  Project ID: ${PROJECT_ID}"
echo "  Region:     ${REGION}"
echo "  CA Pool:    ${CA_POOL_NAME}"
echo "  Root CA:    ${ROOT_CA_NAME}"
echo "=============================================================================="

echo "[Step 1/2] Disabling and deleting CAS Root CA '${ROOT_CA_NAME}'..."
gcloud privateca roots disable "${ROOT_CA_NAME}" \
    --pool="${CA_POOL_NAME}" \
    --location="${REGION}" \
    --project="${PROJECT_ID}" \
    --quiet 2>/dev/null || true

gcloud privateca roots delete "${ROOT_CA_NAME}" \
    --pool="${CA_POOL_NAME}" \
    --location="${REGION}" \
    --project="${PROJECT_ID}" \
    --ignore-active-certificates \
    --quiet 2>/dev/null || true

echo "[Step 2/2] Deleting CAS CA Pool '${CA_POOL_NAME}'..."
gcloud privateca pools delete "${CA_POOL_NAME}" \
    --location="${REGION}" \
    --project="${PROJECT_ID}" \
    --quiet 2>/dev/null || true

# Remove local certificate artifacts
rm -f rootCA.pem broker/rootCA.pem client.pem client.key trust_store.yaml

echo "=============================================================================="
echo "GCP CAS CAs and CA Pool successfully removed!"
echo "=============================================================================="
