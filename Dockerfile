FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    fping \
    nmap \
    default-jre \
    gcc \
    python3-dev \
    git \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Set up Java environment
ENV JAVA_HOME=/usr/lib/jvm/default-java

# Install pybatfish and its dependencies first
RUN pip install --no-cache-dir \
    pandas \
    matplotlib \
    networkx \
    pybatfish

# Copy requirements and install other dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV ARTIFACT_DIR=/artifacts
ENV DEFAULT_PORTS=22,443
ENV DEFAULT_CONCURRENCY=200
ENV CONNECT_TIMEOUT=1.5

# Expose API port
EXPOSE 8000

# Run the application
CMD ["uvicorn", "network_discovery.api:app", "--host", "0.0.0.0", "--port", "8000"]