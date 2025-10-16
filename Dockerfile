# Use Kali Linux rolling release - ARM64 compatible for Apple Silicon Macs
FROM kalilinux/kali-rolling:latest

# Set working directory
WORKDIR /app

# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1

# Update and install Python and essential dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-venv \
    curl \
    wget \
    git \
    ca-certificates \
    libcap2-bin \
    bsdmainutils \
    && rm -rf /var/lib/apt/lists/*

# Install comprehensive Kali security tools - ARM64 optimized
# Network Reconnaissance & Scanning
# Note: masscan removed - requires raw socket privileges not available in Docker MCP
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    dnsutils \
    dnsrecon \
    dnsenum \
    fierce \
    whois \
    netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

# Web Application Testing
RUN apt-get update && apt-get install -y --no-install-recommends \
    nikto \
    wpscan \
    sqlmap \
    dirb \
    ffuf \
    gobuster \
    wfuzz \
    whatweb \
    wafw00f \
    && rm -rf /var/lib/apt/lists/*

# SSL/TLS Testing
RUN apt-get update && apt-get install -y --no-install-recommends \
    sslscan \
    sslyze \
    && rm -rf /var/lib/apt/lists/*

# SMB & Windows Enumeration
RUN apt-get update && apt-get install -y --no-install-recommends \
    enum4linux \
    nbtscan \
    smbclient \
    crackmapexec \
    responder \
    && rm -rf /var/lib/apt/lists/*

# Password & Credential Testing
RUN apt-get update && apt-get install -y --no-install-recommends \
    hydra \
    john \
    hashcat \
    && rm -rf /var/lib/apt/lists/*

# Vulnerability Research & Exploitation
RUN apt-get update && apt-get install -y --no-install-recommends \
    exploitdb \
    metasploit-framework \
    nuclei \
    && rm -rf /var/lib/apt/lists/*

# OSINT & Information Gathering
RUN apt-get update && apt-get install -y --no-install-recommends \
    theharvester \
    && rm -rf /var/lib/apt/lists/*

# Install Go-based tools not in apt repos (subfinder, amass)
RUN apt-get update && apt-get install -y --no-install-recommends golang-go && \
    export GOPATH=/tmp/go && \
    export PATH=$PATH:$GOPATH/bin && \
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install -v github.com/owasp-amass/amass/v4/...@master && \
    mv $GOPATH/bin/subfinder /usr/local/bin/ && \
    mv $GOPATH/bin/amass /usr/local/bin/ && \
    apt-get remove -y golang-go && \
    apt-get autoremove -y && \
    rm -rf $GOPATH && \
    rm -rf /var/lib/apt/lists/*

# Install testssl.sh from GitHub (not available in apt repos)
RUN git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl && \
    ln -s /opt/testssl/testssl.sh /usr/local/bin/testssl

# Update Metasploit database and exploit-db
RUN msfdb init || true && \
    searchsploit -u || true

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip3 install --no-cache-dir --break-system-packages -r requirements.txt

# Copy the server code
COPY kali_pentest_server.py .

# Create non-root user with necessary permissions
RUN useradd -m -u 1000 pentest && \
    chown -R pentest:pentest /app

# Fix nmap permission issue for Docker MCP compatibility
# Docker MCP Gateway runs containers with --security-opt no-new-privileges
# This blocks setcap capabilities from working. We must remove them for nmap to execute.
# All nmap scans use -sT (TCP connect) and -Pn flags which don't require raw sockets.
RUN setcap -r /usr/bin/nmap 2>/dev/null || true && \
    setcap -r /usr/lib/nmap/nmap 2>/dev/null || true

# Switch to non-root user for security
USER pentest

# Run the MCP server
CMD ["python3", "kali_pentest_server.py"]
