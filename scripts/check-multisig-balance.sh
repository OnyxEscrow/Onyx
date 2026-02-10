#!/bin/bash
# Check Multisig Wallet Balance
# Opens multisig wallets and checks their balance

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
ESCROW_ID="${1:-37a6b49a-7ddf-4afa-9890-59bc7fa18243}"
WALLET_DIR="/var/monero/wallets"
RPC_BUYER="http://127.0.0.1:18082/json_rpc"
RPC_VENDOR="http://127.0.0.1:18083/json_rpc"
RPC_ARBITER="http://127.0.0.1:18084/json_rpc"

echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}   Multisig Wallet Balance Checker${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "Escrow ID: ${YELLOW}$ESCROW_ID${NC}"
echo ""

# Function to call Monero RPC
call_rpc() {
    local rpc_url=$1
    local method=$2
    local params=$3

    curl -s -X POST "$rpc_url" \
        -H "Content-Type: application/json" \
        -d "{\"jsonrpc\":\"2.0\",\"id\":\"0\",\"method\":\"$method\",\"params\":$params}"
}

# Function to open wallet
open_wallet() {
    local rpc_url=$1
    local wallet_name=$2
    local role=$3

    echo -e "${BLUE}📂 Opening $role wallet: ${YELLOW}$wallet_name${NC}"

    # Close any open wallet first
    call_rpc "$rpc_url" "close_wallet" "{}" > /dev/null 2>&1 || true
    sleep 0.5

    # Open the wallet
    local result=$(call_rpc "$rpc_url" "open_wallet" "{\"filename\":\"$wallet_name\",\"password\":\"\"}")

    if echo "$result" | grep -q "error"; then
        echo -e "${RED}❌ Failed to open wallet${NC}"
        echo "$result" | jq '.error.message' 2>/dev/null || echo "$result"
        return 1
    fi

    echo -e "${GREEN}✅ Wallet opened successfully${NC}"
    sleep 0.5
    return 0
}

# Function to check if wallet is multisig
check_multisig() {
    local rpc_url=$1
    local role=$2

    echo -e "${BLUE}🔍 Checking multisig status for $role...${NC}"

    local result=$(call_rpc "$rpc_url" "is_multisig" "{}")

    if echo "$result" | grep -q "error"; then
        echo -e "${RED}❌ Error checking multisig status${NC}"
        echo "$result" | jq '.error.message' 2>/dev/null || echo "$result"
        return 1
    fi

    local is_multisig=$(echo "$result" | jq -r '.result.multisig')
    local ready=$(echo "$result" | jq -r '.result.ready')
    local threshold=$(echo "$result" | jq -r '.result.threshold')
    local total=$(echo "$result" | jq -r '.result.total')

    if [ "$is_multisig" = "true" ]; then
        echo -e "${GREEN}✅ Multisig: YES${NC}"
        echo -e "   Configuration: ${YELLOW}${threshold}-of-${total}${NC}"
        echo -e "   Ready: ${YELLOW}${ready}${NC}"
        return 0
    else
        echo -e "${RED}❌ Multisig: NO${NC}"
        return 1
    fi
}

# Function to get wallet address
get_address() {
    local rpc_url=$1
    local role=$2

    echo -e "${BLUE}📍 Getting $role address...${NC}"

    local result=$(call_rpc "$rpc_url" "get_address" "{\"account_index\":0}")

    if echo "$result" | grep -q "error"; then
        echo -e "${RED}❌ Error getting address${NC}"
        return 1
    fi

    local address=$(echo "$result" | jq -r '.result.address')
    echo -e "   Address: ${YELLOW}${address}${NC}"
    echo ""
}

# Function to get balance
get_balance() {
    local rpc_url=$1
    local role=$2

    echo -e "${BLUE}💰 Checking $role balance...${NC}"

    local result=$(call_rpc "$rpc_url" "get_balance" "{\"account_index\":0}")

    if echo "$result" | grep -q "error"; then
        echo -e "${RED}❌ Error getting balance${NC}"
        echo "$result" | jq '.error.message' 2>/dev/null || echo "$result"
        return 1
    fi

    local balance=$(echo "$result" | jq -r '.result.balance')
    local unlocked=$(echo "$result" | jq -r '.result.unlocked_balance')

    # Convert atomic units to XMR (1 XMR = 10^12 atomic units)
    local balance_xmr=$(echo "scale=12; $balance / 1000000000000" | bc)
    local unlocked_xmr=$(echo "scale=12; $unlocked / 1000000000000" | bc)

    echo -e "   Total Balance:    ${GREEN}${balance_xmr} XMR${NC} (${balance} atomic units)"
    echo -e "   Unlocked Balance: ${GREEN}${unlocked_xmr} XMR${NC} (${unlocked} atomic units)"

    if [ "$balance" -gt 0 ]; then
        echo -e "${GREEN}✅ Wallet has funds!${NC}"
    else
        echo -e "${YELLOW}⚠️  Wallet is empty${NC}"
    fi
    echo ""

    return 0
}

# Function to refresh wallet (sync with blockchain)
refresh_wallet() {
    local rpc_url=$1
    local role=$2

    echo -e "${BLUE}🔄 Refreshing $role wallet (syncing with blockchain)...${NC}"

    local result=$(call_rpc "$rpc_url" "refresh" "{}")

    if echo "$result" | grep -q "error"; then
        echo -e "${YELLOW}⚠️  Refresh warning (this is normal in offline mode)${NC}"
        return 0
    fi

    echo -e "${GREEN}✅ Wallet refreshed${NC}"
    echo ""
}

# Main execution
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}   BUYER WALLET (RPC: 18082)${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

BUYER_WALLET="buyer_temp_escrow_${ESCROW_ID}"
if open_wallet "$RPC_BUYER" "$BUYER_WALLET" "buyer"; then
    check_multisig "$RPC_BUYER" "buyer"
    get_address "$RPC_BUYER" "buyer"
    refresh_wallet "$RPC_BUYER" "buyer"
    get_balance "$RPC_BUYER" "buyer"
fi

echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}   VENDOR WALLET (RPC: 18083)${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

VENDOR_WALLET="vendor_temp_escrow_${ESCROW_ID}"
if open_wallet "$RPC_VENDOR" "$VENDOR_WALLET" "vendor"; then
    check_multisig "$RPC_VENDOR" "vendor"
    get_address "$RPC_VENDOR" "vendor"
    refresh_wallet "$RPC_VENDOR" "vendor"
    get_balance "$RPC_VENDOR" "vendor"
fi

echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}   ARBITER WALLET (RPC: 18084)${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

ARBITER_WALLET="arbiter_temp_escrow_${ESCROW_ID}"
if open_wallet "$RPC_ARBITER" "$ARBITER_WALLET" "arbiter"; then
    check_multisig "$RPC_ARBITER" "arbiter"
    get_address "$RPC_ARBITER" "arbiter"
    refresh_wallet "$RPC_ARBITER" "arbiter"
    get_balance "$RPC_ARBITER" "arbiter"
fi

echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}✅ Balance check complete!${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "${YELLOW}Note:${NC} All 3 wallets should show the SAME multisig address and balance."
echo -e "${YELLOW}Note:${NC} Multisig address: ${GREEN}9sCrDesy9LK11111111111111111111111111111111118YcC9Gacso6vvEkES46JsBqWdhFAZxqAPkzB6E89FYP8h4p53e${NC}"
echo ""
