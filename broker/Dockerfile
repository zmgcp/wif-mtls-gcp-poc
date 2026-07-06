# ==============================================================================
# broker/Dockerfile - Container packaging for Cloud Run mTLS Token Broker
# ==============================================================================
# Uses lightweight Python 3.11 slim image, configures non-root user execution,
# installs dependencies, and runs under Gunicorn WSGI server.
# ==============================================================================

FROM python:3.11-slim

# Set environment variables for clean Python execution
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8080 \
    ROOT_CA_PATH=/app/rootCA.pem

# Create and set absolute working directory
WORKDIR /app

# Copy requirement specifications first to leverage Docker layer caching
COPY requirements.txt .

# Install dependencies without cache to reduce image size
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code and PKI certificates
COPY . .

# Enforce Principle of Least Privilege: Create and run as non-root system user
RUN useradd -m -u 1000 brokeruser && \
    chown -R brokeruser:brokeruser /app
USER brokeruser

# Expose container port
EXPOSE 8080

# NOTE: In Cloud Run container runtime, binding to 0.0.0.0 inside the isolated container
# network namespace is required by GCP Cloud Run container contract.
# When running locally outside Docker on host OS, app binds to 127.0.0.1 per security guidelines.
ENTRYPOINT ["gunicorn", "--bind", "0.0.0.0:8080", "--workers", "2", "--threads", "4", "--timeout", "60", "--access-logfile", "-", "--error-logfile", "-", "app:app"]
