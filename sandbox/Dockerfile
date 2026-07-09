# Sec-LLM Agent Sandbox — isolated environment for security tool execution
FROM python:3.10-slim

# Install security tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    nikto \
    whatweb \
    dnsutils \
    curl \
    wget \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install Go (for nuclei, ffuf)
RUN apt-get update && apt-get install -y --no-install-recommends golang-go \
    && rm -rf /var/lib/apt/lists/*

# Install Python security tools
RUN pip install --no-cache-dir \
    sqlmap \
    semgrep \
    bandit

# Install Go-based tools
RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
    && go install -v github.com/ffuf/ffuf/v2@latest \
    && cp /root/go/bin/nuclei /usr/local/bin/ \
    && cp /root/go/bin/ffuf /usr/local/bin/

# Create non-root user
RUN useradd -m -s /bin/bash sandbox
USER sandbox
WORKDIR /home/sandbox

# Default: print available tools
CMD ["sh", "-c", "echo 'Sandbox ready. Tools: nmap, sqlmap, nuclei, ffuf, nikto, whatweb, semgrep, bandit'"]
