#!/usr/bin/env bash
# scripts/ubuntu-setup.sh
# Automated Ubuntu development environment setup for Monero Marketplace

set -e  # Exit on error

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${CYAN}"
cat << "EOF"
╔═══════════════════════════════════════╗
║  Monero Marketplace Ubuntu Setup     ║
║  Development Environment Installer   ║
╚═══════════════════════════════════════╝
EOF
echo -e "${NC}"

# Check if running on Ubuntu/Debian
if ! command -v apt &> /dev/null; then
    echo -e "${RED}Error: This script requires Ubuntu/Debian (apt package manager)${NC}"
    exit 1
fi

# Function to check if command exists
command_exists() {
    command -v "$1" &> /dev/null
}

# Function to print step
print_step() {
    echo -e "\n${BLUE}═══ $1 ═══${NC}\n"
}

# 1. Update system
print_step "Step 1: Updating system packages"
sudo apt update
echo -e "${GREEN}✅ System packages updated${NC}"

# 2. Install build dependencies
print_step "Step 2: Installing build dependencies"
sudo apt install -y \
    build-essential \
    pkg-config \
    libssl-dev \
    curl \
    wget \
    git \
    expect \
    jq

echo -e "${GREEN}✅ Build dependencies installed${NC}"

# 3. Install Tor
print_step "Step 3: Installing Tor"
if command_exists tor; then
    echo -e "${YELLOW}Tor already installed${NC}"
else
    sudo apt install -y tor
    sudo systemctl enable tor
    sudo systemctl start tor
    echo -e "${GREEN}✅ Tor installed and started${NC}"
fi

# Verify Tor
if systemctl is-active --quiet tor; then
    echo -e "${GREEN}✅ Tor daemon is running${NC}"

    # Test Tor connection
    if curl -s --socks5-hostname 127.0.0.1:9050 https://check.torproject.org | grep -q "Congratulations"; then
        echo -e "${GREEN}✅ Tor connection verified${NC}"
    else
        echo -e "${YELLOW}⚠️  Tor connection test inconclusive${NC}"
    fi
else
    echo -e "${RED}❌ Tor daemon is not running${NC}"
    exit 1
fi

# 4. Install Rust
print_step "Step 4: Installing Rust toolchain"
if command_exists rustc; then
    echo -e "${YELLOW}Rust already installed: $(rustc --version)${NC}"
else
    echo -e "${CYAN}Installing Rust via rustup...${NC}"
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

    # Load Rust environment
    source "$HOME/.cargo/env"

    echo -e "${GREEN}✅ Rust installed: $(rustc --version)${NC}"
fi

# Install required Rust components
rustup component add rustfmt clippy
echo -e "${GREEN}✅ Rust components installed (rustfmt, clippy)${NC}"

# 5. Install Monero CLI
print_step "Step 5: Installing Monero CLI (testnet)"
MONERO_DIR="$HOME/monero-testnet"

if [[ -d "$MONERO_DIR" ]] && find "$MONERO_DIR" -name "monerod" -type f | grep -q .; then
    echo -e "${YELLOW}Monero CLI already installed at $MONERO_DIR${NC}"
else
    echo -e "${CYAN}Downloading Monero CLI...${NC}"
    mkdir -p "$MONERO_DIR"
    cd "$MONERO_DIR"

    wget -q --show-progress https://downloads.getmonero.org/cli/linux64 -O monero-linux.tar.bz2

    echo -e "${CYAN}Extracting...${NC}"
    tar -xjf monero-linux.tar.bz2
    rm monero-linux.tar.bz2

    echo -e "${GREEN}✅ Monero CLI installed${NC}"
    cd - > /dev/null
fi

# Find monerod path
MONEROD=$(find "$MONERO_DIR" -name "monerod" -type f | head -n 1)
if [[ -z "$MONEROD" ]]; then
    echo -e "${RED}❌ monerod not found${NC}"
    exit 1
fi

MONERO_BIN_DIR=$(dirname "$MONEROD")
echo -e "${CYAN}Monero binaries: $MONERO_BIN_DIR${NC}"
"$MONEROD" --version

# 6. Configure git hooks
print_step "Step 6: Configuring git hooks"
cd "$(git rev-parse --show-toplevel)" || exit 1

# Make all scripts executable
chmod +x scripts/*.sh
echo -e "${GREEN}✅ Scripts made executable${NC}"

# Install pre-commit hook
if [[ -f ".git/hooks/pre-commit" ]]; then
    echo -e "${YELLOW}Pre-commit hook already exists, backing up...${NC}"
    mv .git/hooks/pre-commit .git/hooks/pre-commit.backup
fi

ln -sf ../../scripts/pre-commit.sh .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
echo -e "${GREEN}✅ Git pre-commit hook installed${NC}"

# 7. Build project
print_step "Step 7: Building project"
if cargo build --workspace; then
    echo -e "${GREEN}✅ Project built successfully${NC}"
else
    echo -e "${RED}❌ Build failed${NC}"
    exit 1
fi

# 8. Run tests (without integration tests requiring RPC)
print_step "Step 8: Running tests"
if cargo test --workspace --lib; then
    echo -e "${GREEN}✅ Unit tests passed${NC}"
else
    echo -e "${YELLOW}⚠️  Some tests failed (may require Monero RPC)${NC}"
fi

# 9. Summary
print_step "Installation Complete! 🎉"

echo -e "${GREEN}✅ System Dependencies${NC}"
echo -e "${GREEN}✅ Tor Daemon${NC}"
echo -e "${GREEN}✅ Rust Toolchain${NC}"
echo -e "${GREEN}✅ Monero CLI${NC}"
echo -e "${GREEN}✅ Git Hooks${NC}"
echo -e "${GREEN}✅ Project Build${NC}"

echo -e "\n${CYAN}══════════════════════════════════════${NC}"
echo -e "${CYAN}  Environment Configuration${NC}"
echo -e "${CYAN}══════════════════════════════════════${NC}\n"

echo -e "${YELLOW}Add to ~/.bashrc:${NC}"
cat << EOF

# Monero Marketplace Development
export MONERO_TESTNET_PATH="$MONERO_DIR"
export PATH="\$PATH:$MONERO_BIN_DIR"

# Rust
export PATH="\$PATH:\$HOME/.cargo/bin"

# Aliases
alias test-wallet="cargo test --package wallet -- --nocapture"
alias test-all="cargo test --workspace"
alias lint="cargo clippy --workspace -- -D warnings"
alias fmt="cargo fmt --workspace"
alias precommit="./scripts/pre-commit.sh"
EOF

echo -e "\n${CYAN}══════════════════════════════════════${NC}"
echo -e "${CYAN}  Next Steps${NC}"
echo -e "${CYAN}══════════════════════════════════════${NC}\n"

echo -e "1. ${YELLOW}Reload shell configuration:${NC}"
echo -e "   ${GREEN}source ~/.bashrc${NC}"
echo ""
echo -e "2. ${YELLOW}Start Monero testnet:${NC}"
echo -e "   ${GREEN}./scripts/setup-monero-testnet.sh${NC}"
echo ""
echo -e "3. ${YELLOW}Run integration tests:${NC}"
echo -e "   ${GREEN}cargo test --package wallet${NC}"
echo ""
echo -e "4. ${YELLOW}Read documentation:${NC}"
echo -e "   ${GREEN}cat UBUNTU-SETUP.md${NC}"
echo -e "   ${GREEN}cat CLAUDE.md${NC}"
echo ""
echo -e "5. ${YELLOW}Run security checks:${NC}"
echo -e "   ${GREEN}./scripts/pre-commit.sh${NC}"
echo ""

echo -e "${CYAN}══════════════════════════════════════${NC}"
echo -e "${GREEN}Happy coding! 🦀🔐${NC}"
echo -e "${CYAN}══════════════════════════════════════${NC}\n"
