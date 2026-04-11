FROM python:3.12-slim

# System deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl git ca-certificates tar && \
    rm -rf /var/lib/apt/lists/*

# Gitleaks
RUN ARCH=$(uname -m | sed 's/x86_64/x64/;s/aarch64/arm64/') && \
    curl -sSL "https://github.com/gitleaks/gitleaks/releases/download/v8.18.4/gitleaks_8.18.4_linux_${ARCH}.tar.gz" \
    | tar -xz -C /usr/local/bin gitleaks && \
    chmod +x /usr/local/bin/gitleaks

# Semgrep
RUN pip install --no-cache-dir semgrep

WORKDIR /app
COPY . .

RUN pip install --no-cache-dir ".[api]"

# Data directory for SQLite
RUN mkdir -p /data
ENV LOOPSEC_WORK_DIR=/data

EXPOSE 8000

CMD ["uvicorn", "loopsec.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
