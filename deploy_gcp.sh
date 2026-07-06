#!/usr/bin/env bash
# ==============================================================================
# deploy_gcp.sh - Automated GCP Deployment & WIF Configuration Script
# ==============================================================================
# This script deploys the mTLS token broker to Cloud Run, configures Google
# Cloud Workload Identity Federation (WIF) Pool and OIDC Provider, and binds
# the required IAM permissions to allow the authenticated X.509 client (client-01)
# to impersonate a target Service Account and access Cloud Storage.
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
SERVICE_NAME="${3:-mtls-token-broker}"
POOL_ID="${4:-demo-cert-pool}"
PROVIDER_ID="${5:-demo-cert-provider}"
BROKER_SA_NAME="${6:-broker-sa}"
TARGET_SA_NAME="${7:-wif-target-sa}"

if [[ -z "${PROJECT_ID}" ]]; then
    echo "ERROR: PROJECT_ID is not set and could not be inferred from gcloud config."
    echo "Usage: ./deploy_gcp.sh <PROJECT_ID> [REGION] [SERVICE_NAME] [POOL_ID] [PROVIDER_ID] [BROKER_SA] [TARGET_SA]"
    exit 1
fi

PROJECT_NUMBER=$(gcloud projects describe "${PROJECT_ID}" --format='value(projectNumber)')
BUCKET_NAME="demo-wif-mtls-${PROJECT_ID}"
WORKSPACE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=============================================================================="
echo "GCP WIF mTLS Broker Deployment Configuration"
echo "=============================================================================="
echo "  Project ID:          ${PROJECT_ID} (Number: ${PROJECT_NUMBER})"
echo "  Region:              ${REGION}"
echo "  Cloud Run Service:   ${SERVICE_NAME}"
echo "  Workload Pool ID:    ${POOL_ID}"
echo "  OIDC Provider ID:    ${PROVIDER_ID}"
echo "  Broker SA:           ${BROKER_SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"
echo "  Target SA:           ${TARGET_SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"
echo "  Test GCS Bucket:     gs://${BUCKET_NAME}"
echo "=============================================================================="

# ==============================================================================
# 2. Enable Required Google Cloud APIs
# ==============================================================================
echo "[Step 1/8] Enabling required GCP APIs..."
gcloud services enable \
    iam.googleapis.com \
    iamcredentials.googleapis.com \
    sts.googleapis.com \
    run.googleapis.com \
    cloudbuild.googleapis.com \
    storage.googleapis.com \
    --project="${PROJECT_ID}"

# ==============================================================================
# 3. Create Service Accounts & Grant Permissions (with IAM retry buffer)
# ==============================================================================
echo "[Step 2/8] Configuring Service Accounts..."

# 3a. Broker Service Account (used by Cloud Run to sign JWTs)
if ! gcloud iam service-accounts describe "${BROKER_SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com" --project="${PROJECT_ID}" >/dev/null 2>&1; then
    gcloud iam service-accounts create "${BROKER_SA_NAME}" \
        --display-name="mTLS WIF Token Broker SA" \
        --project="${PROJECT_ID}"
    echo "Waiting 10 seconds for broker-sa IAM propagation across global control planes..."
    sleep 10
fi

# Grant Token Creator role to Broker SA on ITSELF so it can call signJwt
echo "Granting roles/iam.serviceAccountTokenCreator to Broker SA..."
retry_cmd gcloud iam service-accounts add-iam-policy-binding "${BROKER_SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com" \
    --role="roles/iam.serviceAccountTokenCreator" \
    --member="serviceAccount:${BROKER_SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com" \
    --project="${PROJECT_ID}" --quiet >/dev/null

# 3b. Target Service Account (to be impersonated by the external client)
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
echo "[Step 3/8] Configuring test Cloud Storage bucket: gs://${BUCKET_NAME}..."
if ! gcloud storage buckets describe "gs://${BUCKET_NAME}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
    gcloud storage buckets create "gs://${BUCKET_NAME}" \
        --project="${PROJECT_ID}" \
        --location="${REGION}" \
        --uniform-bucket-level-access
fi

# Upload a test dummy file to verify listing later
echo "Hello from mTLS WIF Authentication Demo! Date: $(date -u)" > "${WORKSPACE_DIR}/demo_object.txt"
gcloud storage cp "${WORKSPACE_DIR}/demo_object.txt" "gs://${BUCKET_NAME}/demo_object.txt" --project="${PROJECT_ID}" --quiet
rm -f "${WORKSPACE_DIR}/demo_object.txt"

# Grant Object Viewer role to Target SA on the bucket (wrapped in retry for SA propagation)
echo "Granting roles/storage.objectViewer to Target SA on bucket..."
retry_cmd gcloud storage buckets add-iam-policy-binding "gs://${BUCKET_NAME}" \
    --role="roles/storage.objectViewer" \
    --member="serviceAccount:${TARGET_SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com" \
    --project="${PROJECT_ID}" --quiet >/dev/null

# ==============================================================================
# 5. Ensure PKI Certificates Exist & Copy to Broker Directory
# ==============================================================================
echo "[Step 4/8] Verifying PKI certificate setup..."
if [[ ! -f "${WORKSPACE_DIR}/rootCA.pem" ]] || [[ ! -f "${WORKSPACE_DIR}/client.pem" ]]; then
    echo "PKI certificates not found. Running setup_pki.sh..."
    bash "${WORKSPACE_DIR}/setup_pki.sh"
fi

cp -f "${WORKSPACE_DIR}/rootCA.pem" "${WORKSPACE_DIR}/broker/rootCA.pem"

# ==============================================================================
# 6. Build and Deploy Cloud Run Token Broker
# ==============================================================================
echo "[Step 5/8] Deploying token broker to Cloud Run (${SERVICE_NAME})..."

# Initial deploy without WIF provider env var (will update URL after deploy)
gcloud run deploy "${SERVICE_NAME}" \
    --source="${WORKSPACE_DIR}/broker" \
    --project="${PROJECT_ID}" \
    --region="${REGION}" \
    --service-account="${BROKER_SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com" \
    --ingress="all" \
    --allow-unauthenticated \
    --set-env-vars="ROOT_CA_PATH=/app/rootCA.pem,LOCAL_DEV_MODE=false,SERVICE_ACCOUNT_EMAIL=${BROKER_SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com" \
    --quiet

# Retrieve assigned Cloud Run URL
BROKER_URL=$(gcloud run services describe "${SERVICE_NAME}" --region="${REGION}" --project="${PROJECT_ID}" --format='value(status.url)')
echo "Deployed Cloud Run Broker URL: ${BROKER_URL}"

# ==============================================================================
# 7. Configure Workload Identity Pool and OIDC Provider
# ==============================================================================
echo "[Step 6/8] Configuring Workload Identity Pool (${POOL_ID})..."
if ! gcloud iam workload-identity-pools describe "${POOL_ID}" --location="global" --project="${PROJECT_ID}" >/dev/null 2>&1; then
    gcloud iam workload-identity-pools create "${POOL_ID}" \
        --location="global" \
        --display-name="Demo Cert Auth Pool" \
        --description="Pool for X.509 mTLS Certificate Authentication Demo" \
        --project="${PROJECT_ID}"
fi

WIF_PROVIDER_NAME="https://iam.googleapis.com/projects/${PROJECT_NUMBER}/locations/global/workloadIdentityPools/${POOL_ID}/providers/${PROVIDER_ID}"

echo "[Step 7/8] Configuring Workload Identity OIDC Provider (${PROVIDER_ID})..."
# If provider exists, update it; otherwise create it
if gcloud iam workload-identity-pools providers describe "${PROVIDER_ID}" --workload-identity-pool="${POOL_ID}" --location="global" --project="${PROJECT_ID}" >/dev/null 2>&1; then
    gcloud iam workload-identity-pools providers update-oidc "${PROVIDER_ID}" \
        --workload-identity-pool="${POOL_ID}" \
        --location="global" \
        --issuer-uri="${BROKER_URL}" \
        --allowed-audiences="${WIF_PROVIDER_NAME},${BROKER_URL},https://sts.googleapis.com,demo-cert-aud" \
        --attribute-mapping="google.subject=assertion.sub" \
        --attribute-condition="assertion.sub == 'client-01'" \
        --project="${PROJECT_ID}"
else
    gcloud iam workload-identity-pools providers create-oidc "${PROVIDER_ID}" \
        --workload-identity-pool="${POOL_ID}" \
        --location="global" \
        --display-name="Demo Cert OIDC Provider" \
        --issuer-uri="${BROKER_URL}" \
        --allowed-audiences="${WIF_PROVIDER_NAME},${BROKER_URL},https://sts.googleapis.com,demo-cert-aud" \
        --attribute-mapping="google.subject=assertion.sub" \
        --attribute-condition="assertion.sub == 'client-01'" \
        --project="${PROJECT_ID}"
fi

# Update Cloud Run broker environment with exact ISSUER_URI and WIF_PROVIDER_NAME
echo "Updating Cloud Run broker with ISSUER_URI=${BROKER_URL} and WIF_PROVIDER_NAME..."
gcloud run services update "${SERVICE_NAME}" \
    --region="${REGION}" \
    --project="${PROJECT_ID}" \
    --update-env-vars="ISSUER_URI=${BROKER_URL},WIF_PROVIDER_NAME=${WIF_PROVIDER_NAME}" \
    --quiet >/dev/null

# ==============================================================================
# 8. Bind IAM Permissions for Target Service Account Impersonation
# ==============================================================================
echo "[Step 8/8] Binding IAM workloadIdentityUser role to Target SA..."
PRINCIPAL="principal://iam.googleapis.com/projects/${PROJECT_NUMBER}/locations/global/workloadIdentityPools/${POOL_ID}/subject/client-01"

retry_cmd gcloud iam service-accounts add-iam-policy-binding "${TARGET_SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com" \
    --role="roles/iam.workloadIdentityUser" \
    --member="${PRINCIPAL}" \
    --project="${PROJECT_ID}" --quiet >/dev/null

# ==============================================================================
# 9. Generate Client Configuration File (client_config.json)
# ==============================================================================
CONFIG_FILE="${WORKSPACE_DIR}/client_config.json"
cat <<EOF > "${CONFIG_FILE}"
{
    "broker_url": "${BROKER_URL}",
    "project_id": "${PROJECT_ID}",
    "project_number": "${PROJECT_NUMBER}",
    "pool_id": "${POOL_ID}",
    "provider_id": "${PROVIDER_ID}",
    "wif_provider_name": "${WIF_PROVIDER_NAME}",
    "target_sa": "${TARGET_SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com",
    "bucket_name": "${BUCKET_NAME}",
    "principal": "${PRINCIPAL}"
}
EOF

echo "=============================================================================="
echo "GCP WIF mTLS Authentication Demo Successfully Deployed!"
echo "=============================================================================="
echo "  Broker URL:        ${BROKER_URL}"
echo "  WIF Pool:          ${POOL_ID}"
echo "  WIF Provider:      ${PROVIDER_ID}"
echo "  Target SA:         ${TARGET_SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"
echo "  Allowed Principal: ${PRINCIPAL}"
echo "  Test GCS Bucket:   gs://${BUCKET_NAME}"
echo ""
echo "Client configuration generated at: ${CONFIG_FILE}"
echo "To execute the client test script, run:"
echo "  python3 client.py --config client_config.json"
echo "=============================================================================="
