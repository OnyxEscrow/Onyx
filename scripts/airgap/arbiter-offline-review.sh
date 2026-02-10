#!/bin/bash
# Arbiter Offline Dispute Review Tool
#
# This script runs on the AIR-GAPPED arbiter laptop (Tails USB)
# It helps the arbiter review disputes and sign decisions offline
#
# SECURITY REQUIREMENTS:
# - Run ONLY on air-gapped laptop (NEVER connected to internet)
# - Tails OS (amnesic, leaves no traces)
# - Persistent volume encrypted for arbiter wallet
# - USB readonly for evidence (no write access)
#
# WORKFLOW:
# 1. Scan QR code from server (dispute request)
# 2. Review evidence from USB readonly
# 3. Make decision (buyer or vendor)
# 4. Sign with arbiter wallet offline
# 5. Generate QR code for server to scan
#
# DEPENDENCIES:
# - zbarcam (QR scanner)
# - qrencode (QR generator)
# - monero-wallet-cli (for signing)
# - jq (JSON parsing)

set -e  # Exit on error

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DISPUTE_DIR="$HOME/arbiter-disputes"
WALLET_PATH="$HOME/Persistent/arbiter-wallet"
EVIDENCE_MOUNT="/media/amnesia/EVIDENCE"  # USB readonly mount point

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Banner
echo -e "${BLUE}"
cat << "EOF"
╔══════════════════════════════════════════════════════════╗
║                                                          ║
║     MONERO MARKETPLACE - ARBITER OFFLINE TOOL           ║
║                                                          ║
║     🔒 AIR-GAPPED DISPUTE RESOLUTION 🔒                 ║
║                                                          ║
║     WARNING: This laptop must NEVER connect to          ║
║              the internet. Disconnect all network       ║
║              devices before proceeding.                 ║
║                                                          ║
╚══════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

# Check dependencies
echo -e "${YELLOW}[*] Checking dependencies...${NC}"

command -v zbarcam >/dev/null 2>&1 || {
    echo -e "${RED}Error: zbarcam not installed.${NC}"
    echo "Install with: sudo apt install zbar-tools"
    exit 1
}

command -v qrencode >/dev/null 2>&1 || {
    echo -e "${RED}Error: qrencode not installed.${NC}"
    echo "Install with: sudo apt install qrencode"
    exit 1
}

command -v jq >/dev/null 2>&1 || {
    echo -e "${RED}Error: jq not installed.${NC}"
    echo "Install with: sudo apt install jq"
    exit 1
}

command -v monero-wallet-cli >/dev/null 2>&1 || {
    echo -e "${RED}Error: monero-wallet-cli not found.${NC}"
    echo "Install Monero from: https://www.getmonero.org/downloads/"
    exit 1
}

echo -e "${GREEN}✓ All dependencies satisfied${NC}\n"

# Check network isolation
echo -e "${YELLOW}[*] Verifying network isolation...${NC}"

if ip link show | grep -E "UP.*state UP" | grep -qv "lo:"; then
    echo -e "${RED}╔════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║  WARNING: NETWORK INTERFACE DETECTED!             ║${NC}"
    echo -e "${RED}║                                                    ║${NC}"
    echo -e "${RED}║  This laptop appears to be connected to a         ║${NC}"
    echo -e "${RED}║  network. For maximum security, disconnect ALL    ║${NC}"
    echo -e "${RED}║  network devices (WiFi, Ethernet) before          ║${NC}"
    echo -e "${RED}║  proceeding with arbiter duties.                  ║${NC}"
    echo -e "${RED}╚════════════════════════════════════════════════════╝${NC}"
    echo ""
    read -p "Continue anyway? (NOT RECOMMENDED) [y/N]: " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
else
    echo -e "${GREEN}✓ Network isolated (no active interfaces)${NC}\n"
fi

# Create dispute directory if not exists
mkdir -p "$DISPUTE_DIR"

# Main menu
while true; do
    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}  ARBITER MENU${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════${NC}"
    echo ""
    echo "1) 📥 Import new dispute (scan QR code)"
    echo "2) 📋 List pending disputes"
    echo "3) 🔍 Review dispute evidence"
    echo "4) ⚖️  Make decision and sign"
    echo "5) 📤 Export decision (generate QR code)"
    echo "6) 🔐 Check arbiter wallet status"
    echo "7) 🚪 Exit"
    echo ""
    read -p "Select option [1-7]: " choice

    case $choice in
        1)
            echo -e "\n${YELLOW}[*] Import Dispute via QR Code${NC}"
            echo ""
            echo "Position QR code in front of camera and press ENTER..."
            read -p ""

            # Capture QR code
            echo "Scanning... (press 'q' when QR captured)"
            DISPUTE_JSON=$(zbarcam --raw --oneshot 2>/dev/null | head -1)

            if [ -z "$DISPUTE_JSON" ]; then
                echo -e "${RED}✗ Failed to scan QR code${NC}"
                continue
            fi

            # Validate JSON
            echo "$DISPUTE_JSON" | jq . >/dev/null 2>&1 || {
                echo -e "${RED}✗ Invalid JSON in QR code${NC}"
                continue
            }

            # Extract escrow ID
            ESCROW_ID=$(echo "$DISPUTE_JSON" | jq -r '.escrow_id')

            if [ "$ESCROW_ID" == "null" ] || [ -z "$ESCROW_ID" ]; then
                echo -e "${RED}✗ Invalid dispute data (missing escrow_id)${NC}"
                continue
            fi

            # Save dispute
            DISPUTE_FILE="$DISPUTE_DIR/dispute_${ESCROW_ID}.json"
            echo "$DISPUTE_JSON" | jq . > "$DISPUTE_FILE"

            echo -e "${GREEN}✓ Dispute imported: $ESCROW_ID${NC}"
            echo ""
            echo "Summary:"
            echo "  Escrow ID: $ESCROW_ID"
            echo "  Amount: $(echo "$DISPUTE_JSON" | jq -r '.amount') piconeros"
            echo "  Opened: $(date -d @$(echo "$DISPUTE_JSON" | jq -r '.dispute_opened_at') 2>/dev/null || echo 'N/A')"
            echo "  Evidence files: $(echo "$DISPUTE_JSON" | jq -r '.evidence_file_count')"
            echo ""
            echo "Next step: Review evidence (option 3)"
            ;;

        2)
            echo -e "\n${YELLOW}[*] Pending Disputes${NC}"
            echo ""

            DISPUTES=$(find "$DISPUTE_DIR" -name "dispute_*.json" 2>/dev/null)

            if [ -z "$DISPUTES" ]; then
                echo "No pending disputes."
            else
                echo "ID                                    | Amount (XMR) | Status"
                echo "--------------------------------------|--------------|--------"

                for dispute_file in $DISPUTES; do
                    ESCROW_ID=$(jq -r '.escrow_id' "$dispute_file")
                    AMOUNT_PICONEROS=$(jq -r '.amount' "$dispute_file")
                    AMOUNT_XMR=$(echo "scale=12; $AMOUNT_PICONEROS / 1000000000000" | bc)

                    # Check if decision exists
                    DECISION_FILE="$DISPUTE_DIR/decision_${ESCROW_ID}.json"
                    if [ -f "$DECISION_FILE" ]; then
                        STATUS="✅ Decided"
                    else
                        STATUS="⏳ Pending"
                    fi

                    echo "$ESCROW_ID | $AMOUNT_XMR | $STATUS"
                done
            fi
            ;;

        3)
            echo -e "\n${YELLOW}[*] Review Dispute Evidence${NC}"
            echo ""

            # List disputes
            DISPUTES=$(find "$DISPUTE_DIR" -name "dispute_*.json" 2>/dev/null)
            if [ -z "$DISPUTES" ]; then
                echo "No disputes to review."
                continue
            fi

            # Select dispute
            echo "Select dispute to review:"
            select dispute_file in $DISPUTES "Cancel"; do
                if [ "$dispute_file" == "Cancel" ]; then
                    break
                fi

                if [ -n "$dispute_file" ]; then
                    ESCROW_ID=$(jq -r '.escrow_id' "$dispute_file")

                    echo ""
                    echo -e "${BLUE}═══════════════════════════════════════════════════${NC}"
                    echo -e "${BLUE}  DISPUTE DETAILS${NC}"
                    echo -e "${BLUE}═══════════════════════════════════════════════════${NC}"
                    echo ""
                    jq -r '"Escrow ID: \(.escrow_id)
Buyer ID: \(.buyer_id)
Vendor ID: \(.vendor_id)
Amount: \(.amount) piconeros (\((.amount / 1000000000000) * 100 | floor / 100) XMR)
Dispute Opened: " + (.dispute_opened_at | tostring) + "

BUYER CLAIM:
\(.buyer_claim)

VENDOR RESPONSE:
\(.vendor_response // "No response provided")

Evidence Files: \(.evidence_file_count)
"' "$dispute_file"

                    echo ""
                    echo -e "${YELLOW}Evidence Location:${NC} $EVIDENCE_MOUNT/$ESCROW_ID/"
                    echo ""

                    # Check if USB mounted
                    if [ -d "$EVIDENCE_MOUNT" ]; then
                        echo "Evidence files:"
                        ls -lh "$EVIDENCE_MOUNT/$ESCROW_ID/" 2>/dev/null || echo "  (No evidence directory found)"
                        echo ""
                        echo "Open file manager? [y/N]:"
                        read -n 1 -r
                        echo
                        if [[ $REPLY =~ ^[Yy]$ ]]; then
                            nautilus "$EVIDENCE_MOUNT/$ESCROW_ID/" 2>/dev/null &
                        fi
                    else
                        echo -e "${RED}⚠ Evidence USB not mounted at $EVIDENCE_MOUNT${NC}"
                        echo "Insert USB and mount readonly:"
                        echo "  sudo mount -o ro /dev/sdX1 $EVIDENCE_MOUNT"
                    fi

                    break
                fi
            done
            ;;

        4)
            echo -e "\n${YELLOW}[*] Make Decision and Sign${NC}"
            echo ""

            # Select dispute
            DISPUTES=$(find "$DISPUTE_DIR" -name "dispute_*.json" 2>/dev/null | grep -v "decision_")
            if [ -z "$DISPUTES" ]; then
                echo "No disputes pending decision."
                continue
            fi

            echo "Select dispute to decide:"
            select dispute_file in $DISPUTES "Cancel"; do
                if [ "$dispute_file" == "Cancel" ]; then
                    break
                fi

                if [ -n "$dispute_file" ]; then
                    ESCROW_ID=$(jq -r '.escrow_id' "$dispute_file")
                    NONCE=$(jq -r '.nonce' "$dispute_file")
                    PARTIAL_TX=$(jq -r '.partial_tx_hex' "$dispute_file")

                    echo ""
                    echo "Dispute: $ESCROW_ID"
                    echo ""
                    echo "Who should receive the funds?"
                    echo "1) Buyer (buyer was right)"
                    echo "2) Vendor (vendor was right)"
                    echo "3) Cancel"
                    echo ""
                    read -p "Decision [1-3]: " decision_choice

                    case $decision_choice in
                        1)
                            DECISION="buyer"
                            ;;
                        2)
                            DECISION="vendor"
                            ;;
                        *)
                            echo "Decision cancelled."
                            break
                            ;;
                    esac

                    echo ""
                    read -p "Reason for decision: " REASON

                    if [ -z "$REASON" ]; then
                        echo -e "${RED}Error: Reason cannot be empty${NC}"
                        break
                    fi

                    echo ""
                    echo -e "${YELLOW}[*] Signing transaction with arbiter wallet...${NC}"
                    echo ""

                    # TODO: Integrate with monero-wallet-cli to sign partial_tx
                    # For now, placeholder
                    echo "⚠ Manual step required:"
                    echo ""
                    echo "1. Open monero-wallet-cli:"
                    echo "   monero-wallet-cli --wallet-file $WALLET_PATH"
                    echo ""
                    echo "2. Sign the multisig transaction:"
                    echo "   sign_multisig $PARTIAL_TX"
                    echo ""
                    echo "3. Copy the signed_tx_hex from output"
                    echo ""
                    read -p "Paste signed_tx_hex here: " SIGNED_TX

                    if [ -z "$SIGNED_TX" ]; then
                        echo -e "${RED}Error: Signed TX cannot be empty${NC}"
                        break
                    fi

                    # Generate decision signature
                    # Message = BLAKE2b(escrow_id || nonce || decision || signed_tx_hex)
                    MESSAGE_HASH=$(echo -n "${ESCROW_ID}${NONCE}${DECISION}${SIGNED_TX}" | b2sum -b | awk '{print $1}')

                    echo ""
                    echo "Sign this message hash with arbiter wallet:"
                    echo "$MESSAGE_HASH"
                    echo ""
                    echo "In monero-wallet-cli, run:"
                    echo "  sign $MESSAGE_HASH"
                    echo ""
                    read -p "Paste signature here: " DECISION_SIGNATURE

                    if [ -z "$DECISION_SIGNATURE" ]; then
                        echo -e "${RED}Error: Signature cannot be empty${NC}"
                        break
                    fi

                    # Create decision JSON
                    DECIDED_AT=$(date +%s)
                    DECISION_FILE="$DISPUTE_DIR/decision_${ESCROW_ID}.json"

                    cat > "$DECISION_FILE" <<-EOF
{
  "escrow_id": "$ESCROW_ID",
  "nonce": "$NONCE",
  "decision": "$DECISION",
  "reason": "$REASON",
  "signed_tx_hex": "$SIGNED_TX",
  "decision_signature": "$DECISION_SIGNATURE",
  "decided_at": $DECIDED_AT
}
EOF

                    echo ""
                    echo -e "${GREEN}✓ Decision saved: $DECISION_FILE${NC}"
                    echo ""
                    echo "Next step: Export decision QR (option 5)"

                    break
                fi
            done
            ;;

        5)
            echo -e "\n${YELLOW}[*] Export Decision via QR Code${NC}"
            echo ""

            # Select decision
            DECISIONS=$(find "$DISPUTE_DIR" -name "decision_*.json" 2>/dev/null)
            if [ -z "$DECISIONS" ]; then
                echo "No decisions to export."
                continue
            fi

            echo "Select decision to export:"
            select decision_file in $DECISIONS "Cancel"; do
                if [ "$decision_file" == "Cancel" ]; then
                    break
                fi

                if [ -n "$decision_file" ]; then
                    ESCROW_ID=$(jq -r '.escrow_id' "$decision_file")

                    echo ""
                    echo "Generating QR code for decision: $ESCROW_ID"
                    echo ""

                    # Generate QR code (display in terminal and save PNG)
                    QR_FILE="$DISPUTE_DIR/decision_${ESCROW_ID}_qr.png"
                    cat "$decision_file" | jq -c . | qrencode -o "$QR_FILE" -s 10

                    # Display QR in terminal
                    cat "$decision_file" | jq -c . | qrencode -t ANSIUTF8

                    echo ""
                    echo -e "${GREEN}✓ QR code generated: $QR_FILE${NC}"
                    echo ""
                    echo "Show this QR code to the server's camera to import the decision."
                    echo ""
                    echo "Open QR image? [y/N]:"
                    read -n 1 -r
                    echo
                    if [[ $REPLY =~ ^[Yy]$ ]]; then
                        xdg-open "$QR_FILE" 2>/dev/null &
                    fi

                    break
                fi
            done
            ;;

        6)
            echo -e "\n${YELLOW}[*] Arbiter Wallet Status${NC}"
            echo ""

            if [ ! -f "$WALLET_PATH" ]; then
                echo -e "${RED}⚠ Arbiter wallet not found at: $WALLET_PATH${NC}"
                echo ""
                echo "Create a new wallet:"
                echo "  monero-wallet-cli --generate-new-wallet $WALLET_PATH --testnet"
                echo ""
            else
                echo -e "${GREEN}✓ Wallet exists: $WALLET_PATH${NC}"
                echo ""
                echo "To check balance:"
                echo "  monero-wallet-cli --wallet-file $WALLET_PATH --testnet"
                echo ""
                echo "To export public key:"
                echo "  In wallet: address"
                echo "             spendkey"
                echo "             viewkey"
            fi
            ;;

        7)
            echo -e "\n${GREEN}Exiting arbiter tool. Stay secure!${NC}"
            exit 0
            ;;

        *)
            echo -e "${RED}Invalid option. Please select 1-7.${NC}"
            ;;
    esac
done
