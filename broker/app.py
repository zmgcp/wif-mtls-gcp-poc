#!/usr/bin/env python3
# ==============================================================================
# broker/app.py - mTLS Token Broker for GCP Workload Identity Federation (WIF)
# ==============================================================================
# This Flask application acts as a custom OIDC token broker designed for Cloud Run.
# It cryptographically validates X.509 client certificates presented over mTLS against
# a trusted Root CA, extracts the Subject Common Name (CN), and delegates OIDC ID
# token signing to Google Cloud IAM Credentials API (signJwt) without storing keys.
# ==============================================================================

import os
import re
import json
import logging
import datetime
import urllib.parse
import base64

from flask import Flask, request, jsonify, make_response
import requests

# Google Cloud Auth and IAM Credentials SDKs
import google.auth
from google.auth.transport.requests import Request as GCPRequest
from google.cloud import iam_credentials_v1

# Cryptography library for X.509 certificate and signature validation
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.backends import default_backend

# Configure logging per Mandatory Secure Web Skills (Diagnostic logging without sensitive secrets)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("mTLS-Token-Broker")

app = Flask(__name__)

# ==============================================================================
# Configuration & Environment Variables
# ==============================================================================
# ISSUER_URI: Must match exactly the --issuer-uri configured in GCP WIF OIDC Provider
ISSUER_URI_ENV = os.getenv("ISSUER_URI", "")
# WIF_PROVIDER_NAME: Full resource name of the WIF provider or allowed audience
WIF_PROVIDER_NAME = os.getenv("WIF_PROVIDER_NAME", "demo-cert-aud")
# ROOT_CA_PATH: Absolute path to the trusted Root CA certificate for mTLS verification
ROOT_CA_PATH = os.path.abspath(os.getenv("ROOT_CA_PATH", os.path.join(os.path.dirname(__file__), "rootCA.pem")))
# LOCAL_DEV_MODE: When True, uses ephemeral in-memory RSA key instead of GCP IAM signJwt
LOCAL_DEV_MODE = os.getenv("LOCAL_DEV_MODE", "false").lower() == "true"

# ==============================================================================
# Local Development Mode Ephemeral RSA Key Setup (Multi-tiered Fallback)
# ==============================================================================
# Per Mandatory Secure Web Skills: Never hardcode secrets or fallback literal strings.
# For local offline testing, we generate an ephemeral in-memory RSA key pair at startup
# and log a severe warning regarding horizontal scalability and production isolation.
EPHEMERAL_PRIVATE_KEY = None
EPHEMERAL_PUBLIC_JWKS = None

if LOCAL_DEV_MODE:
    logger.warning("=" * 78)
    logger.warning("SECURITY WARNING: Running in LOCAL_DEV_MODE!")
    logger.warning("Generating ephemeral 2048-bit RSA key in-memory for OIDC token signing.")
    logger.warning("Instance-isolated! Do NOT use in horizontal production deployments!")
    logger.warning("TODO(security): Ensure LOCAL_DEV_MODE is disabled in GCP production.")
    logger.warning("=" * 78)
    
    EPHEMERAL_PRIVATE_KEY = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    # Construct JWKS representation of the ephemeral RSA public key
    pub_numbers = EPHEMERAL_PRIVATE_KEY.public_key().public_numbers()
    def int_to_base64url(val: int) -> str:
        val_bytes = val.to_bytes((val.bit_length() + 7) // 8, byteorder='big')
        return base64.urlsafe_b64encode(val_bytes).rstrip(b'=').decode('ascii')
    
    EPHEMERAL_PUBLIC_JWKS = {
        "keys": [
            {
                "kty": "RSA",
                "alg": "RS256",
                "use": "sig",
                "kid": "local-dev-ephemeral-key-1",
                "n": int_to_base64url(pub_numbers.n),
                "e": int_to_base64url(pub_numbers.e)
            }
        ]
    }


def get_issuer_uri() -> str:
    """Returns the configured ISSUER_URI or dynamically resolves from request host."""
    if ISSUER_URI_ENV:
        return ISSUER_URI_ENV.rstrip('/')
    # Dynamically resolve from request for local development / dynamic Cloud Run
    scheme = request.headers.get("X-Forwarded-Proto", request.scheme)
    return f"{scheme}://{request.host}".rstrip('/')


def get_service_account_email() -> str:
    """
    Retrieves the email of the attached Google Cloud Service Account.
    Checks environment variable, GCP Metadata Server, and default credentials.
    """
    sa_email = os.getenv("SERVICE_ACCOUNT_EMAIL")
    if sa_email:
        return sa_email

    # Attempt to query Google Cloud Metadata Server
    try:
        meta_url = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email"
        resp = requests.get(meta_url, headers={"Metadata-Flavor": "Google"}, timeout=2)
        if resp.status_code == 200:
            sa_email = resp.text.strip()
            logger.info(f"Retrieved Service Account email from GCP Metadata Server: {sa_email}")
            return sa_email
    except Exception as e:
        logger.debug(f"Could not query GCP Metadata Server: {e}")

    # Fallback to google.auth default credentials
    try:
        credentials, _ = google.auth.default()
        if hasattr(credentials, "service_account_email") and credentials.service_account_email:
            return credentials.service_account_email
        # If credentials need refreshing to populate email
        if hasattr(credentials, "refresh"):
            credentials.refresh(GCPRequest())
            if hasattr(credentials, "service_account_email") and credentials.service_account_email:
                return credentials.service_account_email
    except Exception as e:
        logger.debug(f"Could not retrieve service account from google.auth.default: {e}")

    # If all methods fail and we are not in LOCAL_DEV_MODE, raise error
    if not LOCAL_DEV_MODE:
        raise RuntimeError("Unable to determine attached GCP Service Account email for signJwt.")
    return "local-dev-broker@localhost"


# ==============================================================================
# Security Headers Middleware
# ==============================================================================
@app.after_request
def apply_security_headers(response):
    """
    Enforces mandatory HTTP security headers on all outgoing responses per
    Mandatory Secure Web Skills (Default HTTP Headers & Cache-Control).
    """
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none';"
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    return response


# ==============================================================================
# Cryptographic X.509 Client Certificate Validation
# ==============================================================================
def extract_and_verify_client_cert() -> str:
    """
    Extracts the client X.509 certificate from HTTP headers or WSGI socket,
    cryptographically validates it against rootCA.pem, checks validity dates,
    and extracts the Subject Common Name (CN).
    """
    cert_pem_str = None

    # 1. Check X-Forwarded-Client-Cert (XFCC) header (Standard GCP LB / Envoy mTLS)
    xfcc = request.headers.get("X-Forwarded-Client-Cert")
    if xfcc:
        logger.debug(f"Received XFCC header: {xfcc[:60]}...")
        # Envoy/LB format: Hash=...;Cert="<url_encoded_pem>";... or raw PEM
        cert_match = re.search(r'Cert="?([^";]+)"?', xfcc, re.IGNORECASE)
        if cert_match:
            cert_pem_str = urllib.parse.unquote(cert_match.group(1))
        else:
            cert_pem_str = urllib.parse.unquote(xfcc)

    # 2. Check X-Client-Cert header (Fallback for standalone Cloud Run PoC testing)
    if not cert_pem_str:
        client_cert_hdr = request.headers.get("X-Client-Cert") or request.headers.get("X-SSL-Client-Cert")
        if client_cert_hdr:
            logger.debug("Received X-Client-Cert header.")
            cert_pem_str = urllib.parse.unquote(client_cert_hdr)

    # 3. Check WSGI socket environment (Direct Gunicorn mTLS termination)
    if not cert_pem_str:
        for key in ["SSL_CLIENT_CERT", "HTTP_X_SSL_CLIENT_CERT", "peercert"]:
            if key in request.environ and request.environ[key]:
                cert_pem_str = request.environ[key]
                logger.debug(f"Extracted client cert from WSGI environ[{key}].")
                break

    if not cert_pem_str:
        logger.warning("Authentication failed: No client X.509 certificate presented in request.")
        raise ValueError("Client X.509 certificate required for mTLS authentication.")

    # 4. Load Trusted Root CA Certificate from disk
    if not os.path.exists(ROOT_CA_PATH):
        logger.error(f"Root CA file not found at absolute path: {ROOT_CA_PATH}")
        raise RuntimeError("Server PKI misconfiguration: Root CA certificate file missing.")

    try:
        with open(ROOT_CA_PATH, "rb") as f:
            root_ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
    except Exception as e:
        logger.error(f"Failed to load Root CA certificate from {ROOT_CA_PATH}: {e}")
        raise RuntimeError("Server PKI misconfiguration: Invalid Root CA certificate.")

    # 5. Parse Client X.509 Certificate
    try:
        if isinstance(cert_pem_str, str):
            cert_bytes = cert_pem_str.encode("utf-8")
        else:
            cert_bytes = cert_pem_str
        client_cert = x509.load_pem_x509_certificate(cert_bytes, default_backend())
    except Exception as e:
        logger.warning(f"Failed to parse client certificate PEM: {e}")
        raise ValueError("Invalid client certificate format.")

    # 6. Validate Certificate Expiration Dates
    now = datetime.datetime.now(datetime.timezone.utc)
    not_before = getattr(client_cert, "not_valid_before_utc", None) or client_cert.not_valid_before.replace(tzinfo=datetime.timezone.utc)
    not_after = getattr(client_cert, "not_valid_after_utc", None) or client_cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)

    if now < not_before or now > not_after:
        logger.warning(f"Client cert date validation failed. Now: {now}, Valid: {not_before} to {not_after}")
        raise ValueError(f"Client certificate expired or not yet valid (valid: {not_before.strftime('%Y-%m-%d')} to {not_after.strftime('%Y-%m-%d')}).")

    # 7. Cryptographically Verify Signature against Root CA Public Key
    root_pubkey = root_ca_cert.public_key()
    try:
        if isinstance(root_pubkey, rsa.RSAPublicKey):
            root_pubkey.verify(
                client_cert.signature,
                client_cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                client_cert.signature_hash_algorithm
            )
        elif isinstance(root_pubkey, ec.EllipticCurvePublicKey):
            root_pubkey.verify(
                client_cert.signature,
                client_cert.tbs_certificate_bytes,
                ec.ECDSA(client_cert.signature_hash_algorithm)
            )
        else:
            raise ValueError(f"Unsupported Root CA public key type: {type(root_pubkey)}")
    except Exception as e:
        logger.warning(f"Cryptographic signature verification failed against Root CA: {e}")
        raise ValueError("Client certificate signature verification failed against trusted Root CA.")

    # 8. Extract Subject Common Name (CN)
    cn_attrs = client_cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    if not cn_attrs:
        logger.warning("Client certificate Subject does not contain a Common Name (CN) attribute.")
        raise ValueError("Client certificate Subject missing required Common Name (CN).")

    client_cn = cn_attrs[0].value

    # 9. Strict Input Allow-List Validation per Mandatory Secure Web Skills
    # Prevent injection by enforcing strict alphanumeric/hyphen/underscore format
    if not re.match(r"^[a-zA-Z0-9._-]+$", client_cn):
        logger.warning(f"Client CN '{client_cn}' rejected by security allow-list regex.")
        raise ValueError(f"Client certificate CN contains illegal characters: '{client_cn}'.")

    logger.info(f"Successfully authenticated client certificate for Subject CN: '{client_cn}'")
    return client_cn


# ==============================================================================
# OIDC Token Signing (Google Cloud IAM signJwt vs Local Ephemeral Fallback)
# ==============================================================================
def sign_oidc_token_with_iam(payload: dict) -> str:
    """
    Calls Google Cloud IAM Credentials API (iamcredentials.projects.serviceAccounts.signJwt)
    to cryptographically sign the OIDC ID token payload without storing private keys locally.
    """
    if LOCAL_DEV_MODE:
        logger.info("LOCAL_DEV_MODE enabled: Using in-memory ephemeral RSA key to sign JWT.")
        return sign_jwt_locally(payload)

    sa_email = get_service_account_email()
    name = f"projects/-/serviceAccounts/{sa_email}"
    payload_str = json.dumps(payload)

    logger.info(f"Delegating JWT signing to GCP IAM Credentials API for SA: {sa_email}")
    try:
        client = iam_credentials_v1.IAMCredentialsClient()
        response = client.sign_jwt(name=name, payload=payload_str)
        return response.signed_jwt
    except Exception as e:
        logger.error(f"GCP IAM signJwt API call failed: {e}")
        # If in local environment where GCP credentials fail, explain clearly
        raise RuntimeError(f"Failed to sign OIDC token via GCP IAM Credentials API: {e}")


def sign_jwt_locally(payload: dict) -> str:
    """
    Signs JWT locally using ephemeral RSA key in LOCAL_DEV_MODE.
    Uses basic base64url encoding and RS256 cryptography primitives.
    """
    header = {"alg": "RS256", "typ": "JWT", "kid": "local-dev-ephemeral-key-1"}
    
    def b64url(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')
    
    header_b64 = b64url(json.dumps(header, separators=(',', ':')).encode('utf-8'))
    payload_b64 = b64url(json.dumps(payload, separators=(',', ':')).encode('utf-8'))
    signing_input = f"{header_b64}.{payload_b64}".encode('utf-8')
    
    signature = EPHEMERAL_PRIVATE_KEY.sign(
        signing_input,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    sig_b64 = b64url(signature)
    return f"{header_b64}.{payload_b64}.{sig_b64}"


# ==============================================================================
# OIDC Discovery Endpoints
# ==============================================================================
@app.route("/.well-known/openid-configuration", methods=["GET"])
def openid_configuration():
    """
    OIDC Discovery Endpoint representing the broker's metadata and capabilities.
    Google STS queries this endpoint to locate the jwks_uri.
    """
    issuer = get_issuer_uri()
    config = {
        "issuer": issuer,
        "jwks_uri": f"{issuer}/.well-known/jwks.json",
        "response_types_supported": ["id_token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "claims_supported": ["iss", "sub", "aud", "iat", "exp", "client_cn", "auth_time"]
    }
    logger.info(f"Served OIDC configuration for issuer: {issuer}")
    return jsonify(config), 200


@app.route("/.well-known/jwks.json", methods=["GET"])
def jwks():
    """
    JWKS Endpoint representing the broker's public signing keys.
    When using GCP IAM signJwt, proxies Google's public key endpoint for the attached
    service account so Google STS can natively verify tokens signed by signJwt.
    """
    if LOCAL_DEV_MODE and EPHEMERAL_PUBLIC_JWKS:
        logger.info("Served local ephemeral JWKS for LOCAL_DEV_MODE.")
        return jsonify(EPHEMERAL_PUBLIC_JWKS), 200

    try:
        sa_email = get_service_account_email()
        google_jwks_url = f"https://www.googleapis.com/service_accounts/v1/jwk/{sa_email}"
        logger.info(f"Proxying JWKS from Google IAM for SA: {sa_email}")
        
        resp = requests.get(google_jwks_url, timeout=5)
        if resp.status_code == 200:
            return jsonify(resp.json()), 200
        else:
            logger.error(f"Google IAM JWKS endpoint returned HTTP {resp.status_code}: {resp.text}")
            return jsonify({"error": "server_error", "error_description": "Failed to fetch upstream JWKS."}), 502
    except Exception as e:
        logger.error(f"Error serving JWKS: {e}")
        return jsonify({"error": "server_error", "error_description": "Internal error retrieving JWKS."}), 500


# ==============================================================================
# Token Authentication & Issuance Endpoint
# ==============================================================================
@app.route("/token", methods=["POST", "GET"])
def token():
    """
    Token endpoint that authenticates the X.509 client certificate, extracts the
    Subject Common Name (CN), constructs the standardized OIDC JWT claims, and
    returns a short-lived OIDC ID token signed by GCP IAM signJwt.
    """
    try:
        # Step 1: Validate mTLS client certificate & extract Subject CN
        client_cn = extract_and_verify_client_cert()
        
        # Step 2: Standardize OIDC token payload structure per Requirement 2
        now_ts = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
        issuer = get_issuer_uri()
        
        payload = {
            "iss": issuer,
            "sub": client_cn,
            "aud": WIF_PROVIDER_NAME,
            "iat": now_ts,
            "exp": now_ts + 3600,  # Short-lived 1-hour expiration per Least Privilege
            "client_cn": client_cn,
            "auth_time": now_ts
        }
        
        logger.info(f"Constructed OIDC payload for '{client_cn}' (iss: {issuer}, aud: {WIF_PROVIDER_NAME})")
        
        # Step 3: Sign OIDC token via GCP IAM signJwt (keyless signing)
        signed_token = sign_oidc_token_with_iam(payload)
        
        # Step 4: Return standardized OAuth 2.0 / OIDC token response
        response_data = {
            "id_token": signed_token,
            "token_type": "Bearer",
            "expires_in": 3600,
            "sub": client_cn,
            "iss": issuer,
            "aud": WIF_PROVIDER_NAME
        }
        logger.info(f"Successfully issued OIDC ID token for Subject CN: '{client_cn}'")
        return jsonify(response_data), 200

    except ValueError as ve:
        # Client validation / certificate errors (401 Unauthorized / 400 Bad Request)
        logger.warning(f"Token issuance denied due to client validation error: {ve}")
        return jsonify({
            "error": "invalid_client",
            "error_description": str(ve)
        }), 401

    except Exception as e:
        # Server / IAM signing errors (500 Internal Server Error)
        logger.error(f"Unexpected error during token issuance: {e}", exc_info=True)
        return jsonify({
            "error": "server_error",
            "error_description": "Internal authentication broker error."
        }), 500


@app.route("/health", methods=["GET"])
def health():
    """Health check endpoint for Cloud Run / Gunicorn load balancer probes."""
    return jsonify({"status": "healthy", "service": "mtls-token-broker", "local_dev_mode": LOCAL_DEV_MODE}), 200


if __name__ == "__main__":
    # Local debugging execution (binds to 127.0.0.1 per Mandatory Secure Web Skills)
    port = int(os.getenv("PORT", 8080))
    logger.info(f"Starting development server on 127.0.0.1:{port} (LOCAL_DEV_MODE={LOCAL_DEV_MODE})")
    app.run(host="127.0.0.1", port=port, debug=False)
