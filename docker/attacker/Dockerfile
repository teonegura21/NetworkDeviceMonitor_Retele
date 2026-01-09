FROM kalilinux/kali-rolling

# Install security tools
RUN apt-get update && apt-get install -y \
    nmap \
    masscan \
    netcat-openbsd \
    hping3 \
    iproute2 \
    procps \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy scripts
COPY start_attacker.sh /app/start_attacker.sh
COPY attack_scenarios.sh /app/attack_scenarios.sh
RUN chmod +x /app/*.sh

CMD ["/app/start_attacker.sh"]
