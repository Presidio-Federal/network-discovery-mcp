# --- build stage ---
FROM python:3.11-slim AS build

WORKDIR /app

# Install system dependencies for Python builds and network tools
RUN apt-get update && apt-get install -y \
    gcc \
    build-essential \
    python3-dev \
    git \
    default-jre \
    && rm -rf /var/lib/apt/lists/*

# Set up Java environment
ENV JAVA_HOME=/usr/lib/jvm/default-java

# Install pybatfish first to ensure it's properly installed
ENV PYTHONPATH=/usr/local/lib/python3.11/site-packages:/app

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir --upgrade pybatfish && \
    python -c "import pybatfish; from pybatfish.client.session import Session; print(f'Successfully installed pybatfish {pybatfish.__version__} with client.session')"

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir pydantic-settings>=2.0.0 && \
    pip install --no-cache-dir fastmcp>=2.12.0 httpx>=0.25.0

# --- runtime stage ---
FROM python:3.11-slim

WORKDIR /app

# Install lightweight runtime dependencies including nginx and openssl
RUN apt-get update && apt-get install -y \
    openssh-client \
    iputils-ping \
    traceroute \
    nmap \
    fping \
    netcat-openbsd \
    snmp \
    snmpd \
    sshpass \
    curl \
    telnet \
    dnsutils \
    net-tools \
    iproute2 \
    default-jre \
    gcc \
    build-essential \
    python3-dev \
    nginx \
    openssl \
    && rm -rf /var/lib/apt/lists/*

# --- SSL Certificates ---
# Do NOT auto-generate self-signed certs.
# We'll mount /certs/fullchain.pem and /certs/privkey.pem at runtime.
RUN mkdir -p /certs
VOLUME ["/certs"]

# Copy nginx configuration
COPY nginx.conf /etc/nginx/nginx.conf

# Set up Java environment
ENV JAVA_HOME=/usr/lib/jvm/default-java

# Copy installed packages from build stage
COPY --from=build /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=build /usr/local/bin /usr/local/bin

# Copy application code
COPY . .

# Install runtime Python dependencies (ensure same versions)
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir pandas matplotlib networkx pybatfish && \
    pip install --no-cache-dir pydantic-settings>=2.0.0 && \
    pip install --no-cache-dir fastmcp>=2.12.0 httpx>=0.25.0 && \
    python -c "import pybatfish; from pybatfish.client.session import Session; print(f'Successfully installed pybatfish {pybatfish.__version__} with client.session')"

# Environment variables
ENV PYTHONUNBUFFERED=1
ENV ARTIFACT_DIR=/artifacts
ENV DEFAULT_PORTS=22,443
ENV DEFAULT_CONCURRENCY=200
ENV CONNECT_TIMEOUT=1.5
ENV PYTHONPATH=/usr/local/lib/python3.11/site-packages:/app
ENV LOG_LEVEL=info
ENV BATFISH_HOST=batfish
ENV HOST=0.0.0.0
ENV PORT=8080
ENV TRANSPORT=https
ENV ENABLE_MCP=true

# Expose both HTTP and HTTPS ports
EXPOSE 8080 443

# Copy entrypoint script
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Run both nginx and the FastMCP server
ENTRYPOINT ["/entrypoint.sh"]
    