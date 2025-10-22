FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    fping \
    nmap \
    default-jre \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --upgrade pip && pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV ARTIFACT_DIR=/tmp/network_discovery_artifacts
ENV DEFAULT_PORTS=22,443
ENV DEFAULT_CONCURRENCY=200
ENV CONNECT_TIMEOUT=1.5

# Expose API port
EXPOSE 8000

# Run the application
CMD ["uvicorn", "network_discovery.api:app", "--host", "0.0.0.0", "--port", "8000"]