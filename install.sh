#!/usr/bin/env bash
# LoopSec CI installer
# Installs LoopSec + required security tools in a CI environment
#
# Usage:
#   curl -sSf https://raw.githubusercontent.com/kagozi/loopsec/main/install.sh | bash
#   # or
#   wget -qO- https://raw.githubusercontent.com/kagozi/loopsec/main/install.sh | bash

set -euo pipefail

echo "🔒 Installing LoopSec..."

# Install LoopSec from GitHub
pip install --quiet --upgrade pip
pip install --quiet "git+https://github.com/kagozi/loopsec.git"

# Install Semgrep
echo "  Installing Semgrep..."
pip install --quiet semgrep

# Install Gitleaks
echo "  Installing Gitleaks..."
GITLEAKS_VERSION="8.21.2"
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
case "$ARCH" in
  x86_64) ARCH="x64" ;;
  aarch64|arm64) ARCH="arm64" ;;
esac
GITLEAKS_URL="https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_${OS}_${ARCH}.tar.gz"
curl -sSfL "$GITLEAKS_URL" | tar -xz -C /usr/local/bin/ gitleaks 2>/dev/null || \
  curl -sSfL "$GITLEAKS_URL" | tar -xz -C "$HOME/.local/bin/" gitleaks 2>/dev/null || \
  echo "  ⚠ Could not install Gitleaks (optional)"

# Verify
echo ""
echo "✅ LoopSec installed successfully!"
loopsec version
echo ""
echo "  semgrep: $(semgrep --version 2>/dev/null || echo 'not found')"
echo "  gitleaks: $(gitleaks version 2>/dev/null || echo 'not found')"
echo ""
echo "Usage:"
echo "  export OPENAI_API_KEY=sk-..."
echo "  loopsec scan --repo ./your-app"
