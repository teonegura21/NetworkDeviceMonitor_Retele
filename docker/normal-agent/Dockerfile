FROM ubuntu:22.04

# Install basic tools and curl/wget for simulating traffic
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    dnsutils \
    netcat-openbsd \
    iproute2 \
    procps \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the startup script
COPY start_normal.sh /app/start_normal.sh
RUN chmod +x /app/start_normal.sh

# The agent binary is mounted via docker-compose volume
# to /usr/local/bin/nms-agent

CMD ["/app/start_normal.sh"]
