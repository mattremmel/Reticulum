FROM python:3.11-slim

# Install build dependencies for cryptography C extensions
RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc libffi-dev && \
    rm -rf /var/lib/apt/lists/*

# Copy source and install
WORKDIR /app
COPY . .
RUN pip install --no-cache-dir .

# Create config directory
RUN mkdir -p /etc/reticulum

CMD ["rnsd", "--config", "/etc/reticulum", "-vvv"]
