# Google Cloud Workload Identity Federation (WIF) mTLS X.509 Authentication Demo

An enterprise-grade, complete proof-of-concept (PoC) demonstrating how to broker **X.509 Certificate Authentication over Mutual TLS (mTLS)** into **Google Cloud Workload Identity Federation (WIF)**. 

This repository implements the architectural pattern established by **Google Cloud Solutions Architects**, enabling external workloads (on-premises servers, edge devices, or third-party clouds) to securely access Google Cloud resources without storing static, long-lived service account JSON keys.

---

## 🏛️ Architecture Overview

The authentication pipeline eliminates static credentials by establishing a cryptographic trust chain from an on-premises Root CA to Google Cloud IAM:

```
+-------------------+           +-----------------------+           +-----------------------+           +-----------------------+
|  External Client  |           |   mTLS Token Broker   |           |  Google Security Token|           | Google Cloud Storage  |
|   (client-01)     |           |     (Cloud Run)       |           |      Service (STS)    |           |     (Target Bucket)   |
+---------+---------+           +-----------+-----------+           +-----------+-----------+           +-----------+-----------+
          |                                 |                                   |                                   |
          | 1. mTLS POST /token             |                                   |                                   |
          |    (presents client.pem)        |                                   |                                   |
          |-------------------------------->|                                   |                                   |
          |                                 | 2. Cryptographic Cert Validation  |                                   |
          |                                 |    Extract CN ('client-01')       |                                   |
          |                                 |    Call IAM signJwt (Keyless)     |                                   |
          |                                 |--+                                |                                   |
          |                                 |  |                                |                                   |
          |                                 |<-+                                |                                   |
          | 3. Return OIDC ID Token         |                                   |                                   |
          |    (iss: Broker, sub: client-01)|                                   |                                   |
          |<--------------------------------|                                   |                                   |
          |                                                                     |                                   |
          | 4. POST https://sts.googleapis.com/v1/token                         |                                   |
          |    (subject_token: OIDC ID Token)                                   |                                   |
          |-------------------------------------------------------------------->|                                   |
          |                                                                     | 5. GET /.well-known/jwks.json     |
          |                                                                     |    (Proxy SA JWKS from GCP IAM)   |
          |                                                                     |---------------------------------->|
          |                                                                     |                                   |
          |                                                                     | 6. Verify Signature & WIF Rule    |
          |                                                                     |    (assertion.sub == 'client-01') |
          |                                                                     |--+                                |
          |                                                                     |  |                                |
          |                                                                     |<-+                                |
          | 7. Return GCP Federated Access Token                                |                                   |
          |<--------------------------------------------------------------------|                                   |
          |                                                                                                         |
          | 8. POST https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/TARGET_SA:generateAccessToken
          |    (auth: Bearer Federated Access Token)                                                                |
          |-------------------------------------------------------------------------------------------------------->|
          | 9. Return GCP OAuth 2.0 Access Token for Target SA                                                      |
          |<--------------------------------------------------------------------------------------------------------|
          |                                                                                                         |
          | 10. GET https://storage.googleapis.com/storage/v1/b/BUCKET_NAME/o                                       |
          |     (auth: Bearer Impersonated OAuth Token)                                                             |
          |-------------------------------------------------------------------------------------------------------->|
          | 11. Return 200 OK (List of GCS Bucket Objects)                                                          |
          |<--------------------------------------------------------------------------------------------------------|
```

### Key Architectural Highlights
1. **Keyless OIDC Token Signing (`signJwt`)**: The Cloud Run token broker does not store any private signing keys in memory, disk, or environment variables. Instead, it delegates JWT signing to the Google Cloud IAM Credentials API (`iamcredentials.projects.serviceAccounts.signJwt`), leveraging Google-managed ephemeral keys.
2. **JWKS Proxying**: To allow Google STS to verify the signature of tokens signed by `signJwt`, the broker's `/.well-known/jwks.json` endpoint proxies the public JSON Web Key Set (JWKS) published by Google for the broker's attached Service Account (`https://www.googleapis.com/service_accounts/v1/jwk/{service_account_email}`).
3. **Strict Attribute Mapping & RBAC**: In Workload Identity Federation, the token's `sub` claim (derived from the X.509 certificate's Common Name) is mapped to `google.subject`. An IAM policy binding restricts access exclusively to `principal://.../subject/client-01`.

---

## 📁 Repository Structure

```text
.
├── setup_pki.sh            # Generates mock Root CA, server certs, and client cert (CN=client-01)
├── deploy_gcp.sh           # Automates Cloud Run deploy, WIF Pool/Provider setup, and IAM bindings
├── client.py               # End-to-end Python client testing mTLS, STS exchange, IAM impersonation, and GCS
├── requirements.txt        # Root workspace dependencies (for local testing & client script)
└── broker/                 # Cloud Run mTLS Token Broker Service
    ├── app.py              # Flask WSGI application implementing OIDC discovery and signJwt broker
    ├── Dockerfile          # Least-privilege container packaging (non-root execution, Gunicorn)
    └── requirements.txt    # Broker container Python dependencies
```

---

## 🚀 Step-by-Step Quickstart Guide

### Prerequisites
- **Google Cloud SDK (`gcloud`)** installed and authenticated (`gcloud auth login`).
- **Python 3.11+** and **OpenSSL** installed locally.
- A Google Cloud Project with billing enabled.

### Step 1: Generate Mock PKI Certificates
Run the automated OpenSSL script to generate the Root CA, broker server certificate, and authenticated client certificate (`CN=client-01`):

```bash
chmod +x setup_pki.sh deploy_gcp.sh
./setup_pki.sh
```

*Output files generated:*
- `rootCA.pem` / `rootCA.key`: Self-signed Root Certificate Authority (valid for 10 years).
- `server.pem` / `server.key`: Server certificate for local broker HTTPS/mTLS testing.
- `client.pem` / `client.key`: Client certificate with Subject Common Name `CN=client-01`.

---

### Step 2: Local Development & Integration Testing (Offline Mode)
You can test the entire certificate validation, CN extraction, and JWT signing pipeline locally without touching live GCP infrastructure by enabling `LOCAL_DEV_MODE`:

1. **Install Python Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

2. **Start the Broker locally**:
   ```bash
   export LOCAL_DEV_MODE=true
   export PORT=8080
   python3 -m gunicorn --bind 127.0.0.1:8080 broker.app:app
   ```
   *(Note: In `LOCAL_DEV_MODE`, the broker generates an ephemeral in-memory RSA key pair to sign tokens and serve JWKS locally).*

3. **Run the Client Script against Local Broker**:
   In a new terminal window:
   ```bash
   python3 client.py --local-dev
   ```
   *The client will perform the mTLS handshake, present `client.pem`, receive a signed OIDC ID token, and decode/print the verified claims (`sub: client-01`).*

---

### Step 3: Live Google Cloud Deployment & WIF Federation
Deploy the token broker to Cloud Run and configure Workload Identity Federation in your GCP project:

1. **Execute Deployment Script**:
   ```bash
   ./deploy_gcp.sh <YOUR_GCP_PROJECT_ID> us-central1
   ```
   *This script automatically:*
   - Enables required GCP APIs (`iam`, `iamcredentials`, `sts`, `run`, `storage`).
   - Creates `broker-sa` (with `serviceAccountTokenCreator` role on itself for `signJwt`).
   - Creates `wif-target-sa` (with `storage.objectViewer` role on a test GCS bucket).
   - Deploys `broker/` to Google Cloud Run.
   - Creates WIF Pool `demo-cert-pool` and OIDC Provider `demo-cert-provider` pointing to the Cloud Run URL.
   - Binds `roles/iam.workloadIdentityUser` to `principal://.../subject/client-01`.
   - Generates `client_config.json` containing all deployed endpoints and resource IDs.

2. **Execute Full End-to-End WIF Verification**:
   ```bash
   python3 client.py --config client_config.json
   ```
   *The client will execute the complete 4-step pipeline:*
   - **Step 1**: Authenticate to Cloud Run via X.509 certificate -> receive OIDC ID token.
   - **Step 2**: Exchange OIDC token at Google STS (`https://sts.googleapis.com/v1/token`) -> receive GCP Federated Access Token.
   - **Step 3**: Impersonate `wif-target-sa` via IAM Credentials API -> receive GCP OAuth 2.0 Access Token.
   - **Step 4**: Query Google Cloud Storage API -> successfully list objects in the test bucket!

---

## 🔒 Security Controls & Compliance

This PoC strictly adheres to Google Cloud Security best practices and **Mandatory Secure Web Skills**:
- **Zero Stored Secrets**: No private keys, JWT secrets, or API tokens are hardcoded or stored on disk.
- **Strict Input Sanitization**: Certificate Subject CNs are validated against an alphanumeric allow-list regex (`^[a-zA-Z0-9._-]+$`) to prevent claims injection.
- **Least Privilege Execution**: The Docker container executes under a dedicated non-root user (`brokeruser`, UID 1000). Service accounts are strictly segregated by role.
- **Hardened HTTP Headers**: All broker responses enforce `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Content-Security-Policy: default-src 'none'`, and `Cache-Control: no-store`.
- **Diagnostic Logging**: Server and client logs provide clear audit trails without leaking bearer tokens or private cryptographic material.
