#!/usr/bin/env bash
# scripts/check-environment.sh
# Verify complete development environment setup

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Counters
passed=0
failed=0
warnings=0

# Function to check command
check_command() {
    local name="$1"
    local cmd="$2"
    local required="$3"  # "required" or "optional"

    echo -n "  Checking $name... "
    if command -v "$cmd" &> /dev/null; then
        version=$("$cmd" --version 2>&1 | head -n 1)
        echo -e "${GREEN}✅${NC} ($version)"
        ((passed++))
    else
        if [[ "$required" == "required" ]]; then
            echo -e "${RED}❌ Not found (REQUIRED)${NC}"
            ((failed++))
        else
            echo -e "${YELLOW}⚠️  Not found (optional)${NC}"
            ((warnings++))
        fi
    fi
}

# Function to check service
check_service() {
    local name="$1"
    local service="$2"

    echo -n "  Checking $name... "
    if systemctl is-active --quiet "$service"; then
        echo -e "${GREEN}✅ Running${NC}"
        ((passed++))
    else
        echo -e "${RED}❌ Not running${NC}"
        ((failed++))
    fi
}

# Function to check port
check_port() {
    local name="$1"
    local host="$2"
    local port="$3"

    echo -n "  Checking $name ($host:$port)... "
    if timeout 2 bash -c "echo > /dev/tcp/$host/$port" 2>/dev/null; then
        echo -e "${GREEN}✅ Accessible${NC}"
        ((passed++))
    else
        echo -e "${RED}❌ Not accessible${NC}"
        ((failed++))
    fi
}

# Function to check file
check_file() {
    local name="$1"
    local file="$2"

    echo -n "  Checking $name... "
    if [[ -f "$file" ]]; then
        echo -e "${GREEN}✅ Found${NC}"
        ((passed++))
    else
        echo -e "${RED}❌ Not found${NC}"
        ((failed++))
    fi
}

echo -e "${CYAN}"
cat << "EOF"
╔═══════════════════════════════════════╗
║  Environment Check - Monero Market   ║
╚═══════════════════════════════════════╝
EOF
echo -e "${NC}"

# 1. System Tools
echo -e "\n${BLUE}1. System Tools${NC}"
check_command "curl" "curl" "required"
check_command "wget" "wget" "required"
check_command "git" "git" "required"
check_command "jq" "jq" "optional"
check_command "expect" "expect" "optional"

# 2. Build Tools
echo -e "\n${BLUE}2. Build Tools${NC}"
check_command "gcc" "gcc" "required"
check_command "make" "make" "required"
check_command "pkg-config" "pkg-config" "required"

# 3. Rust Toolchain
echo -e "\n${BLUE}3. Rust Toolchain${NC}"
check_command "rustc" "rustc" "required"
check_command "cargo" "cargo" "required"
check_command "rustfmt" "rustfmt" "required"
check_command "clippy" "cargo-clippy" "required"

# 4. Tor
echo -e "\n${BLUE}4. Tor${NC}"
check_command "tor" "tor" "required"

if systemctl --version &> /dev/null; then
    check_service "Tor daemon" "tor"
else
    echo -e "  ${YELLOW}⚠️  systemctl not available (Docker/WSL?)${NC}"
    ((warnings++))
fi

# Test Tor SOCKS proxy
echo -n "  Testing Tor SOCKS proxy... "
if curl -s --max-time 5 --socks5-hostname 127.0.0.1:9050 https://check.torproject.org | grep -q "Congratulations"; then
    echo -e "${GREEN}✅ Working${NC}"
    ((passed++))
else
    echo -e "${RED}❌ Not working${NC}"
    ((failed++))
fi

# 5. Monero
echo -e "\n${BLUE}5. Monero CLI${NC}"
check_command "monerod" "monerod" "required"
check_command "monero-wallet-cli" "monero-wallet-cli" "required"
check_command "monero-wallet-rpc" "monero-wallet-rpc" "required"

# Check if monerod is running
echo -n "  Checking monerod daemon... "
if pgrep -x monerod > /dev/null; then
    echo -e "${GREEN}✅ Running${NC}"
    ((passed++))
else
    echo -e "${YELLOW}⚠️  Not running${NC}"
    ((warnings++))
fi

# Check if wallet-rpc is running
echo -n "  Checking wallet-rpc... "
if pgrep -x monero-wallet-rpc > /dev/null; then
    echo -e "${GREEN}✅ Running${NC}"
    ((passed++))
else
    echo -e "${YELLOW}⚠️  Not running${NC}"
    ((warnings++))
fi

# 6. Network Ports
echo -e "\n${BLUE}6. Network Ports${NC}"

# Check Tor SOCKS
echo -n "  Checking Tor SOCKS (127.0.0.1:9050)... "
if timeout 2 bash -c "echo > /dev/tcp/127.0.0.1/9050" 2>/dev/null; then
    echo -e "${GREEN}✅ Accessible${NC}"
    ((passed++))
else
    echo -e "${RED}❌ Not accessible${NC}"
    ((failed++))
fi

# Check Monero RPC (if running)
echo -n "  Checking Monero RPC (127.0.0.1:18082)... "
if curl -s --max-time 2 -X POST http://127.0.0.1:18082/json_rpc \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","id":"0","method":"get_version"}' | grep -q "result"; then
    echo -e "${GREEN}✅ Accessible${NC}"
    ((passed++))
else
    echo -e "${YELLOW}⚠️  Not accessible (start with: ./scripts/setup-monero-testnet.sh)${NC}"
    ((warnings++))
fi

# 7. Project Structure
echo -e "\n${BLUE}7. Project Structure${NC}"
check_file "CLAUDE.md" "CLAUDE.md"
check_file "Cargo.toml" "Cargo.toml"
check_file "pre-commit hook" ".git/hooks/pre-commit"

# Check if scripts are executable
echo -n "  Checking script permissions... "
if [[ -x "scripts/pre-commit.sh" ]]; then
    echo -e "${GREEN}✅ Executable${NC}"
    ((passed++))
else
    echo -e "${RED}❌ Not executable${NC}"
    ((failed++))
fi

# 8. Project Build
echo -e "\n${BLUE}8. Project Build${NC}"
echo -n "  Checking if project compiles... "
if cargo check --workspace --quiet 2>/dev/null; then
    echo -e "${GREEN}✅ Compiles successfully${NC}"
    ((passed++))
else
    echo -e "${RED}❌ Compilation errors${NC}"
    ((failed++))
fi

# 9. OPSEC Configuration
echo -e "\n${BLUE}9. OPSEC Configuration${NC}"

# Check if Monero RPC is NOT publicly accessible
echo -n "  Verifying Monero RPC isolation... "
if pgrep -x monero-wallet-rpc > /dev/null; then
    # Check if RPC is bound to localhost only
    if netstat -tlnp 2>/dev/null | grep -q "127.0.0.1:18082"; then
        echo -e "${GREEN}✅ Localhost only${NC}"
        ((passed++))
    elif ss -tlnp 2>/dev/null | grep -q "127.0.0.1:18082"; then
        echo -e "${GREEN}✅ Localhost only${NC}"
        ((passed++))
    else
        echo -e "${YELLOW}⚠️  Cannot verify (permissions)${NC}"
        ((warnings++))
    fi
else
    echo -e "${YELLOW}⚠️  RPC not running${NC}"
    ((warnings++))
fi

# Check firewall status
echo -n "  Checking firewall... "
if command -v ufw &> /dev/null; then
    if sudo ufw status | grep -q "Status: active"; then
        echo -e "${GREEN}✅ Active${NC}"
        ((passed++))
    else
        echo -e "${YELLOW}⚠️  Inactive${NC}"
        ((warnings++))
    fi
else
    echo -e "${YELLOW}⚠️  ufw not installed${NC}"
    ((warnings++))
fi

# Summary
echo -e "\n${CYAN}═══════════════════════════════════════${NC}"
echo -e "${CYAN}  Summary${NC}"
echo -e "${CYAN}═══════════════════════════════════════${NC}\n"

total=$((passed + failed + warnings))
echo -e "  ${GREEN}Passed:${NC}   $passed"
echo -e "  ${RED}Failed:${NC}   $failed"
echo -e "  ${YELLOW}Warnings:${NC} $warnings"
echo -e "  ${CYAN}Total:${NC}    $total"
echo ""

if [[ $failed -eq 0 ]]; then
    if [[ $warnings -eq 0 ]]; then
        echo -e "${GREEN}✅ Environment is fully configured!${NC}"
        exit 0
    else
        echo -e "${YELLOW}⚠️  Environment is functional but has warnings${NC}"
        exit 0
    fi
else
    echo -e "${RED}❌ Environment has critical issues${NC}"
    echo -e "\n${YELLOW}Recommendations:${NC}"

    if ! command -v rustc &> /dev/null; then
        echo -e "  - Install Rust: ${CYAN}curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh${NC}"
    fi

    if ! command -v tor &> /dev/null; then
        echo -e "  - Install Tor: ${CYAN}sudo apt install -y tor${NC}"
    fi

    if ! command -v monerod &> /dev/null; then
        echo -e "  - Run setup: ${CYAN}./scripts/ubuntu-setup.sh${NC}"
    fi

    echo -e "\n${CYAN}Or run the automated setup:${NC}"
    echo -e "  ${GREEN}./scripts/ubuntu-setup.sh${NC}\n"

    exit 1
fi
