#!/bin/bash
# ============================================================================
# BountyLedger — Agentic Bug Bounty Pipeline Setup
# Installs all required tools and configures the environment.
# ============================================================================

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}🎯 BountyLedger — Environment Setup${NC}"
echo "============================================"

# --- Go ---
echo -e "\n${YELLOW}[1/6] Checking Go...${NC}"
if command -v go &> /dev/null; then
    echo -e "${GREEN}✓ Go $(go version | awk '{print $3}') is installed${NC}"
else
    echo -e "${RED}✗ Go not found. Installing via Homebrew...${NC}"
    brew install go
fi

# Ensure GOPATH/bin is in PATH
export GOPATH="${GOPATH:-$HOME/go}"
export PATH="$PATH:$GOPATH/bin"

if ! grep -q 'go/bin' ~/.zshrc 2>/dev/null; then
    echo '' >> ~/.zshrc
    echo '# Go binaries' >> ~/.zshrc
    echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.zshrc
    echo -e "${GREEN}✓ Added \$HOME/go/bin to PATH in ~/.zshrc${NC}"
fi

# --- ProjectDiscovery Tools ---
echo -e "\n${YELLOW}[2/6] Installing subfinder (subdomain enumeration)...${NC}"
if command -v subfinder &> /dev/null; then
    echo -e "${GREEN}✓ subfinder already installed${NC}"
else
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
    echo -e "${GREEN}✓ subfinder installed${NC}"
fi

echo -e "\n${YELLOW}[3/6] Installing httpx (HTTP probing)...${NC}"
if command -v httpx &> /dev/null && httpx -version 2>&1 | grep -q "projectdiscovery"; then
    echo -e "${GREEN}✓ httpx (ProjectDiscovery) already installed${NC}"
else
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
    echo -e "${GREEN}✓ httpx installed${NC}"
fi

echo -e "\n${YELLOW}[4/6] Installing katana (web crawler)...${NC}"
if command -v katana &> /dev/null; then
    echo -e "${GREEN}✓ katana already installed${NC}"
else
    go install -v github.com/projectdiscovery/katana/cmd/katana@latest
    echo -e "${GREEN}✓ katana installed${NC}"
fi

echo -e "\n${YELLOW}[5/6] Installing nuclei (vulnerability scanner)...${NC}"
if command -v nuclei &> /dev/null; then
    echo -e "${GREEN}✓ nuclei already installed${NC}"
else
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
    echo -e "${GREEN}✓ nuclei installed${NC}"
fi

echo -e "\n${YELLOW}[6/6] Installing interactsh-client (callback server)...${NC}"
if command -v interactsh-client &> /dev/null; then
    echo -e "${GREEN}✓ interactsh-client already installed${NC}"
else
    go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
    echo -e "${GREEN}✓ interactsh-client installed${NC}"
fi

# --- Python Package ---
echo -e "\n${YELLOW}Installing Python package (editable mode)...${NC}"
cd "$(dirname "$0")"
pip install -e ".[dev]" --quiet
echo -e "${GREEN}✓ bounty CLI installed${NC}"

# --- Verification ---
echo -e "\n${CYAN}============================================${NC}"
echo -e "${CYAN}Verification:${NC}"
echo -e "  subfinder:        $(subfinder -version 2>&1 | head -1 || echo 'NOT FOUND')"
echo -e "  httpx:            $($GOPATH/bin/httpx -version 2>&1 | head -1 || echo 'NOT FOUND')"
echo -e "  katana:           $(katana -version 2>&1 | head -1 || echo 'NOT FOUND')"
echo -e "  nuclei:           $(nuclei -version 2>&1 | head -1 || echo 'NOT FOUND')"
echo -e "  interactsh-client:$(interactsh-client -version 2>&1 | head -1 || echo 'NOT FOUND')"
echo -e "  bounty CLI:       $(bounty --help 2>&1 | head -1 || echo 'NOT FOUND')"

echo -e "\n${GREEN}🎯 Setup complete! Run 'bounty setup' to configure your API keys.${NC}"
