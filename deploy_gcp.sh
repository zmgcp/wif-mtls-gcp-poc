#!/usr/bin/env bash
# ==============================================================================
# deploy_gcp.sh - Automated GCP Deployment & WIF Configuration Script (GA X.509)
# ==============================================================================
# This script configures Google Cloud Workload Identity Federation (WIF) Pool and
# X.509 Provider (GA feature), and binds the required IAM permissions to allow
# the authenticated X.509 client (client-01) to impersonate a target Service Account
# and access Cloud Storage.
#
# Robustness Note: Includes retry loops and propagation buffers to handle
# Google Cloud IAM eventual consistency when creating new service accounts.
# ==============================================================================

set -euo pipefail

# ==============================================================================
# 0. Helper Function: Retry Loop for IAM Eventual Consistency
# ==============================================================================
retry_cmd() {
    local max_attempts=6
    local attempt=1
    local sleep_time=5
    while (( attempt <= max_attempts )); do
        if "$@"; then
            return 0
        fi
        echo "  [Retry ${attempt}/${max_attempts}] IAM propagation in progress... retrying in ${sleep_time}s..."
        sleep "${sleep_time}"
        ((attempt++))
        sleep_time=$((sleep_time + 5))
    done
    echo "ERROR: Command failed after ${max_attempts} attempts."
    return 1
}

# ==============================================================================
# 1. Parameterization & Configuration
# ==============================================================================
PROJECT_ID="${1:-$(gcloud config get-value project 2>/dev/null || echo '')}"
REGION="${2:-us-central1}"
POOL_ID="${3:-demo-cert-pool}"
PROVIDER_ID="${4:-demo-x509-provider}"
TARGET_SA_NAME="${5:-wif-target-sa}"

if [[ -z "${PROJECT_ID}" ]]; then
    echo "ERROR: PROJECT_ID is not set and could not be inferred from gcloud config."
    echo "Usage: ./deploy_gcp.sh <PROJECT_ID> [REGION] [POOL_ID] [PROVIDER_ID] [TARGET_SA]"
    exit 1
fi

PROJECT_NUMBER=$(gcloud projects describe "${PROJECT_ID}" --format='value(projectNumber)')
BUCKET_NAME="demo-wif-mtls-${PROJECT_ID}"
WORKSPACE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=============================================================================="
echo "GCP GA WIF X.509 Federation Deployment Configuration"
echo "=============================================================================="
echo "  Project ID:          ${PROJECT_ID} (Number: ${PROJECT_NUMBER})"
echo "  Region:              ${REGION}"
echo "  Workload Pool ID:    ${POOL_ID}"
echo "  X.509 Provider ID:   ${PROVIDER_ID}"
echo "  Target SA:           ${TARGET_SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"
echo "  Test GCS Bucket:     gs://${BUCKET_NAME}"
echo "=============================================================================="

# ==============================================================================
# 2. Enable Required Google Cloud APIs
# ==============================================================================
echo "[Step 1/7] Enabling required GCP APIs..."
gcloud services enable \
    iam.googleapis.com \
    iamcredentials.googleapis.com \
    sts.googleapis.com \
    storage.googleapis.com \
    privateca.googleapis.com \
    --project="${PROJECT_ID}"

# ==============================================================================
# 3. Create Target Service Account & Grant Permissions
# ==============================================================================
echo "[Step 2/7] Configuring Target Service Account..."
if ! gcloud iam service-accounts describe "${TARGET_SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com" --project="${PROJECT_ID}" >/dev/null 2>&1; then
    gcloud iam service-accounts create "${TARGET_SA_NAME}" \
        --display-name="WIF Target Impersonation SA" \
        --project="${PROJECT_ID}"
    echo "Waiting 10 seconds for wif-target-sa IAM propagation across global control planes..."
    sleep 10
fi

# ==============================================================================
# 4. Create Test Cloud Storage Bucket & Grant Viewer Role to Target SA
# ==============================================================================
echo "[Step 3/7] Configuring test Cloud Storage bucket: gs://${BUCKET_NAME}..."
if ! gcloud storage buckets describe "gs://${BUCKET_NAME}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
    gcloud storage buckets create "gs://${BUCKET_NAME}" \
        --project="${PROJECT_ID}" \
        --location="${REGION}" \
        --uniform-bucket-level-access
fi

echo "Hello from GA Workload Identity Federation X.509 Demo! Date: $(date -u)" > "${WORKSPACE_DIR}/demo_object.txt"
gcloud storage cp "${WORKSPACE_DIR}/demo_object.txt" "gs://${BUCKET_NAME}/demo_object.txt" --project="${PROJECT_ID}" --quiet
rm -f "${WORKSPACE_DIR}/demo_object.txt"

echo "Granting roles/storage.objectViewer to Target SA on bucket..."
retry_cmd gcloud storage buckets add-iam-policy-binding "gs://${BUCKET_NAME}" \
    --role="roles/storage.objectViewer" \
    --member="serviceAccount:${TARGET_SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com" \
    --project="${PROJECT_ID}" --quiet >/dev/null

# ==============================================================================
# 5. Ensure PKI Certificates & Trust Store Exist
# ==============================================================================
echo "[Step 4/7] Verifying PKI certificate & trust store setup..."
if [[ ! -f "${WORKSPACE_DIR}/rootCA.pem" ]] || [[ ! -f "${WORKSPACE_DIR}/client.pem" ]] || [[ ! -f "${WORKSPACE_DIR}/trust_store.yaml" ]]; then
    echo "PKI certificates or trust_store.yaml not found. Running setup_cas.sh..."
    bash "${WORKSPACE_DIR}/setup_cas.sh" "${PROJECT_ID}" "${REGION}"
fi

# ==============================================================================
# 6. Configure Workload Identity Pool and GA X.509 Provider
# ==============================================================================
echo "[Step 5/7] Configuring Workload Identity Pool (${POOL_ID})..."
if ! gcloud iam workload-identity-pools describe "${POOL_ID}" --location="global" --project="${PROJECT_ID}" >/dev/null 2>&1; then
    gcloud iam workload-identity-pools create "${POOL_ID}" \
        --location="global" \
        --display-name="Demo Cert Auth Pool" \
        --description="Pool for GA X.509 mTLS Certificate Authentication Demo" \
        --project="${PROJECT_ID}"
fi

echo "[Step 6/7] Configuring GA Workload Identity X.509 Provider (${PROVIDER_ID})..."
if gcloud iam workload-identity-pools providers describe "${PROVIDER_ID}" --workload-identity-pool="${POOL_ID}" --location="global" --project="${PROJECT_ID}" >/dev/null 2>&1; then
    gcloud iam workload-identity-pools providers update-x509 "${PROVIDER_ID}" \
        --workload-identity-pool="${POOL_ID}" \
        --location="global" \
        --trust-store-config-path="${WORKSPACE_DIR}/trust_store.yaml" \
        --attribute-mapping="google.subject=assertion.subject.dn.cn" \
        --project="${PROJECT_ID}"
else
    gcloud iam workload-identity-pools providers create-x509 "${PROVIDER_ID}" \
        --workload-identity-pool="${POOL_ID}" \
        --location="global" \
        --display-name="Demo Cert X.509 Provider" \
        --trust-store-config-path="${WORKSPACE_DIR}/trust_store.yaml" \
        --attribute-mapping="google.subject=assertion.subject.dn.cn" \
        --project="${PROJECT_ID}"
fi

# ==============================================================================
# 7. Bind IAM Permissions & Generate Client Configuration
# ==============================================================================
echo "[Step 7/7] Binding IAM workloadIdentityUser role & generating client config..."
PRINCIPAL="principal://iam.googleapis.com/projects/${PROJECT_NUMBER}/locations/global/workloadIdentityPools/${POOL_ID}/subject/client-01"

retry_cmd gcloud iam service-accounts add-iam-policy-binding "${TARGET_SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com" \
    --role="roles/iam.workloadIdentityUser" \
    --member="${PRINCIPAL}" \
    --project="${PROJECT_ID}" --quiet >/dev/null

CONFIG_FILE="${WORKSPACE_DIR}/client_config.json"
gcloud iam workload-identity-pools create-cred-config \
    "projects/${PROJECT_NUMBER}/locations/global/workloadIdentityPools/${POOL_ID}/providers/${PROVIDER_ID}" \
    --service-account="${TARGET_SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com" \
    --credential-cert-path="${WORKSPACE_DIR}/client.pem" \
    --credential-cert-private-key-path="${WORKSPACE_DIR}/client.key" \
    --output-file="${CONFIG_FILE}" \
    --project="${PROJECT_ID}"

echo "=============================================================================="
echo "GCP GA WIF X.509 Authentication Demo Successfully Deployed!"
echo "=============================================================================="
echo "  WIF Pool:          ${POOL_ID}"
echo "  WIF X.509 Provider:${PROVIDER_ID}"
echo "  Target SA:         ${TARGET_SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"
echo "  Allowed Principal: ${PRINCIPAL}"
echo "  Test GCS Bucket:   gs://${BUCKET_NAME}"
echo ""
echo "Client configuration generated at: ${CONFIG_FILE}"
echo "To execute the client test script, run:"
echo "  python3 client.py --config client_config.json"
echo "=============================================================================="
