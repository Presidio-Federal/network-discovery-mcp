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
# Use explicit PYTHONPATH to ensure modules can be found
ENV PYTHONPATH=/usr/local/lib/python3.11/site-packages:/app

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir --upgrade pybatfish && \
    python -c "import pybatfish; print(f'Successfully installed pybatfish {pybatfish.__version__}')"

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# --- runtime stage ---
FROM python:3.11-slim

WORKDIR /app

# Install lightweight runtime dependencies
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
    && rm -rf /var/lib/apt/lists/*

# Set up Java environment
ENV JAVA_HOME=/usr/lib/jvm/default-java

# Copy installed packages from build stage
COPY --from=build /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=build /usr/local/bin /usr/local/bin

# Copy application code
COPY . .

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV ARTIFACT_DIR=/artifacts
ENV DEFAULT_PORTS=22,443
ENV DEFAULT_CONCURRENCY=200
ENV CONNECT_TIMEOUT=1.5
ENV PYTHONPATH=/usr/local/lib/python3.11/site-packages:/app

# Expose API port
EXPOSE 8000

# Run the application
CMD ["uvicorn", "network_discovery.api:app", "--host", "0.0.0.0", "--port", "8000"]