#!/bin/bash
# Status Check for All NEXUS Services
# Displays the current running status of all required services

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Get project root directory
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

echo ""
echo -e "${BLUE}════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}   NEXUS MARKETPLACE - SERVICE STATUS${NC}"
echo -e "${BLUE}════════════════════════════════════════════════════════════${NC}"
echo ""

# ═══════════════════════════════════════════════════════════════════════
# 1. TOR DAEMON STATUS
# ═══════════════════════════════════════════════════════════════════════
echo -e "${BLUE}1. Tor Daemon${NC}"

if systemctl is-active --quiet tor 2>/dev/null; then
    echo -e "   Status: ${GREEN}RUNNING${NC}"
    echo -e "   SOCKS Proxy: 127.0.0.1:9050"

    # Test Tor connectivity
    if curl --socks5-hostname 127.0.0.1:9050 --max-time 5 https://check.torproject.org &>/dev/null; then
        echo -e "   Connectivity: ${GREEN}OK${NC}"
    else
        echo -e "   Connectivity: ${YELLOW}NOT WORKING${NC}"
    fi
else
    echo -e "   Status: ${RED}NOT RUNNING${NC}"
    echo -e "   Start with: sudo systemctl start tor"
fi

echo ""

# ═══════════════════════════════════════════════════════════════════════
# 2. MONERO WALLET RPC STATUS
# ═══════════════════════════════════════════════════════════════════════
echo -e "${BLUE}2. Monero Wallet RPC (Testnet)${NC}"

# Check if wallet RPC responds
if curl -s http://127.0.0.1:18083/json_rpc -H 'Content-Type: application/json' \
   -d '{"jsonrpc":"2.0","id":"0","method":"get_version"}' &>/dev/null; then

    echo -e "   Status: ${GREEN}RUNNING${NC}"
    echo -e "   Port: 18083"

    # Get version if possible
    VERSION=$(curl -s http://127.0.0.1:18083/json_rpc -H 'Content-Type: application/json' \
        -d '{"jsonrpc":"2.0","id":"0","method":"get_version"}' | jq -r '.result.version // "unknown"' 2>/dev/null)

    if [ -n "$VERSION" ] && [ "$VERSION" != "null" ] && [ "$VERSION" != "unknown" ]; then
        echo -e "   Version: $VERSION"
    fi

    # Check if PID file exists
    if [ -f "$PROJECT_ROOT/.monero-wallets/wallet-rpc.pid" ]; then
        WALLET_PID=$(cat "$PROJECT_ROOT/.monero-wallets/wallet-rpc.pid")
        if kill -0 "$WALLET_PID" 2>/dev/null; then
            echo -e "   PID: $WALLET_PID"
        fi
    fi

    # Check log file
    if [ -f "$PROJECT_ROOT/.monero-wallets/wallet-rpc.log" ]; then
        LOG_SIZE=$(du -h "$PROJECT_ROOT/.monero-wallets/wallet-rpc.log" | cut -f1)
        echo -e "   Log: wallet-rpc.log ($LOG_SIZE)"
    fi
else
    echo -e "   Status: ${RED}NOT RUNNING${NC}"
    echo -e "   Start with: ./scripts/start-all-services.sh"
fi

echo ""

# ═══════════════════════════════════════════════════════════════════════
# 3. IPFS DAEMON STATUS
# ═══════════════════════════════════════════════════════════════════════
echo -e "${BLUE}3. IPFS Daemon${NC}"

if curl -s http://127.0.0.1:5001/api/v0/version &>/dev/null; then
    echo -e "   Status: ${GREEN}RUNNING${NC}"
    echo -e "   API Port: 5001"

    # Get version
    VERSION=$(curl -s http://127.0.0.1:5001/api/v0/version | jq -r '.Version // "unknown"' 2>/dev/null)
    if [ -n "$VERSION" ] && [ "$VERSION" != "null" ] && [ "$VERSION" != "unknown" ]; then
        echo -e "   Version: $VERSION"
    fi

    # Check if PID file exists
    if [ -f "$PROJECT_ROOT/.ipfs-daemon.pid" ]; then
        IPFS_PID=$(cat "$PROJECT_ROOT/.ipfs-daemon.pid")
        if kill -0 "$IPFS_PID" 2>/dev/null; then
            echo -e "   PID: $IPFS_PID"
        fi
    fi

    # Get peer count
    PEER_COUNT=$(curl -s -X POST http://127.0.0.1:5001/api/v0/swarm/peers | jq '.Peers | length' 2>/dev/null || echo "unknown")
    echo -e "   Peers: $PEER_COUNT"
else
    echo -e "   Status: ${YELLOW}NOT RUNNING${NC} (optional)"
    echo -e "   Reputation export unavailable"
fi

echo ""

# ═══════════════════════════════════════════════════════════════════════
# 4. NEXUS SERVER STATUS
# ═══════════════════════════════════════════════════════════════════════
echo -e "${BLUE}4. NEXUS Server${NC}"

if curl -s http://127.0.0.1:8080/health &>/dev/null; then
    echo -e "   Status: ${GREEN}RUNNING${NC}"
    echo -e "   URL: http://127.0.0.1:8080"

    # Check if PID file exists
    if [ -f "$PROJECT_ROOT/.server.pid" ]; then
        SERVER_PID=$(cat "$PROJECT_ROOT/.server.pid")
        if kill -0 "$SERVER_PID" 2>/dev/null; then
            echo -e "   PID: $SERVER_PID"

            # Get CPU and memory usage
            if command -v ps &> /dev/null; then
                CPU=$(ps -p "$SERVER_PID" -o %cpu= 2>/dev/null | xargs)
                MEM=$(ps -p "$SERVER_PID" -o %mem= 2>/dev/null | xargs)
                RSS=$(ps -p "$SERVER_PID" -o rss= 2>/dev/null | awk '{printf "%.1f MB", $1/1024}')

                if [ -n "$CPU" ]; then
                    echo -e "   CPU: ${CPU}%"
                fi
                if [ -n "$MEM" ]; then
                    echo -e "   Memory: ${MEM}% ($RSS)"
                fi

                # Get uptime
                STARTED=$(ps -p "$SERVER_PID" -o lstart= 2>/dev/null)
                if [ -n "$STARTED" ]; then
                    UPTIME=$(ps -p "$SERVER_PID" -o etime= 2>/dev/null | xargs)
                    echo -e "   Uptime: $UPTIME"
                fi
            fi
        fi
    fi

    # Check log file
    if [ -f "$PROJECT_ROOT/server.log" ]; then
        LOG_SIZE=$(du -h "$PROJECT_ROOT/server.log" | cut -f1)
        LOG_LINES=$(wc -l < "$PROJECT_ROOT/server.log")
        echo -e "   Log: server.log ($LOG_SIZE, $LOG_LINES lines)"

        # Check for recent errors
        RECENT_ERRORS=$(tail -n 100 "$PROJECT_ROOT/server.log" | grep -i "error" | wc -l)
        if [ "$RECENT_ERRORS" -gt 0 ]; then
            echo -e "   Recent Errors: ${YELLOW}$RECENT_ERRORS in last 100 lines${NC}"
        fi
    fi

    # Check active connections (if netstat available)
    if command -v netstat &> /dev/null; then
        CONNECTIONS=$(netstat -an | grep ":8080" | grep ESTABLISHED | wc -l)
        echo -e "   Active Connections: $CONNECTIONS"
    fi
else
    echo -e "   Status: ${RED}NOT RUNNING${NC}"
    echo -e "   Start with: ./scripts/start-all-services.sh"

    # Check if server.log has recent errors
    if [ -f "$PROJECT_ROOT/server.log" ]; then
        echo -e "   ${YELLOW}Check server.log for errors${NC}"
        LAST_ERROR=$(tail -n 50 "$PROJECT_ROOT/server.log" | grep -i "error" | tail -n 1)
        if [ -n "$LAST_ERROR" ]; then
            echo -e "   Last Error: $(echo "$LAST_ERROR" | cut -c1-80)..."
        fi
    fi
fi

echo ""

# ═══════════════════════════════════════════════════════════════════════
# 5. BACKGROUND SERVICES STATUS (if server running)
# ═══════════════════════════════════════════════════════════════════════
if curl -s http://127.0.0.1:8080/health &>/dev/null; then
    echo -e "${BLUE}5. Background Services${NC}"

    # Check if background services are mentioned in logs
    if [ -f "$PROJECT_ROOT/server.log" ]; then
        # TimeoutMonitor
        if grep -q "TimeoutMonitor background service started" "$PROJECT_ROOT/server.log" 2>/dev/null; then
            echo -e "   TimeoutMonitor: ${GREEN}STARTED${NC} (escrow timeout monitoring)"
        fi

        # BlockchainMonitor
        if grep -q "BlockchainMonitor background service started" "$PROJECT_ROOT/server.log" 2>/dev/null; then
            echo -e "   BlockchainMonitor: ${GREEN}STARTED${NC} (30s polling interval)"
        fi

        # MultisigAutoCoordinator
        if grep -q "MultisigAutoCoordinator background service started" "$PROJECT_ROOT/server.log" 2>/dev/null; then
            echo -e "   MultisigAutoCoordinator: ${GREEN}STARTED${NC} (5s polling interval)"
        fi

        # WasmMultisigStore
        if grep -q "WasmMultisigStore initialized" "$PROJECT_ROOT/server.log" 2>/dev/null; then
            echo -e "   WasmMultisigStore: ${GREEN}INITIALIZED${NC} (WASM multisig coordination)"
        fi
    fi

    echo ""
fi

# ═══════════════════════════════════════════════════════════════════════
# 6. DATABASE STATUS
# ═══════════════════════════════════════════════════════════════════════
echo -e "${BLUE}6. Database${NC}"

if [ -f "$PROJECT_ROOT/marketplace.db" ]; then
    DB_SIZE=$(du -h "$PROJECT_ROOT/marketplace.db" | cut -f1)
    echo -e "   Status: ${GREEN}EXISTS${NC}"
    echo -e "   Size: $DB_SIZE"

    # Check if diesel CLI is available
    if command -v diesel &> /dev/null; then
        # Check migrations
        PENDING=$(DATABASE_URL=marketplace.db diesel migration list 2>/dev/null | grep -c "\[ \]" || echo "0")
        APPLIED=$(DATABASE_URL=marketplace.db diesel migration list 2>/dev/null | grep -c "\[X\]" || echo "unknown")

        if [ "$APPLIED" != "unknown" ]; then
            echo -e "   Migrations Applied: $APPLIED"
        fi

        if [ "$PENDING" -gt 0 ]; then
            echo -e "   Pending Migrations: ${YELLOW}$PENDING${NC}"
            echo -e "   ${YELLOW}Run: DATABASE_URL=marketplace.db diesel migration run${NC}"
        fi
    fi

    # Check table count
    if command -v sqlite3 &> /dev/null; then
        TABLE_COUNT=$(sqlite3 marketplace.db "SELECT COUNT(*) FROM sqlite_master WHERE type='table';" 2>/dev/null || echo "unknown")
        if [ "$TABLE_COUNT" != "unknown" ]; then
            echo -e "   Tables: $TABLE_COUNT"
        fi
    fi
else
    echo -e "   Status: ${RED}NOT FOUND${NC}"
    echo -e "   Create with: DATABASE_URL=marketplace.db diesel migration run"
fi

echo ""

# ═══════════════════════════════════════════════════════════════════════
# 7. SUMMARY
# ═══════════════════════════════════════════════════════════════════════
echo -e "${BLUE}════════════════════════════════════════════════════════════${NC}"

# Count running services
RUNNING_COUNT=0
TOTAL_SERVICES=4

systemctl is-active --quiet tor 2>/dev/null && ((RUNNING_COUNT++))
curl -s http://127.0.0.1:18083/json_rpc -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","id":"0","method":"get_version"}' &>/dev/null && ((RUNNING_COUNT++))
curl -s http://127.0.0.1:5001/api/v0/version &>/dev/null && ((RUNNING_COUNT++))
curl -s http://127.0.0.1:8080/health &>/dev/null && ((RUNNING_COUNT++))

if [ "$RUNNING_COUNT" -eq "$TOTAL_SERVICES" ]; then
    echo -e "   ${GREEN}All services running ($RUNNING_COUNT/$TOTAL_SERVICES)${NC} ✅"
elif [ "$RUNNING_COUNT" -gt 0 ]; then
    echo -e "   ${YELLOW}Partial services running ($RUNNING_COUNT/$TOTAL_SERVICES)${NC} ⚠️"
else
    echo -e "   ${RED}No services running ($RUNNING_COUNT/$TOTAL_SERVICES)${NC} ❌"
fi

echo -e "${BLUE}════════════════════════════════════════════════════════════${NC}"
echo ""

# Provide helpful commands
if [ "$RUNNING_COUNT" -lt "$TOTAL_SERVICES" ]; then
    echo -e "${YELLOW}Commands:${NC}"
    echo -e "  Start all services : ${GREEN}./scripts/start-all-services.sh${NC}"
    echo -e "  Stop all services  : ${RED}./scripts/stop-all-services.sh${NC}"
    echo ""
fi
