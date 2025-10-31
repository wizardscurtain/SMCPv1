# SMCP Security Framework Docker Image
FROM python:3.11-slim

# Set metadata
LABEL maintainer="SMCP Security Team <security@smcp-framework.org>"
LABEL description="Secure Model Context Protocol (SMCP) v1 Security Framework"
LABEL version="1.0.0"

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV SMCP_HOST=0.0.0.0
ENV SMCP_PORT=8080
ENV SMCP_LOG_LEVEL=INFO

# Create non-root user for security
RUN groupadd -r smcp && useradd -r -g smcp smcp

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements first for better caching
COPY SMCPv1/code/requirements.txt .
COPY SMCPv1/code/requirements-dev.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY SMCPv1/code/smcp_security/ ./smcp_security/
COPY deployment/docker/entrypoint.sh .
COPY deployment/docker/config.json ./config.json

# Create directories for logs and data
RUN mkdir -p /app/logs /app/data && \
    chown -R smcp:smcp /app

# Make entrypoint executable
RUN chmod +x entrypoint.sh

# Switch to non-root user
USER smcp

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Set entrypoint
ENTRYPOINT ["./entrypoint.sh"]
CMD ["--server"]
