#!/bin/bash
# generate-arbiter-keypair.sh - Generate Ed25519 keypair for offline arbiter
#
# SECURITY: Run this script on the OFFLINE arbiter machine (Tails USB)
# The private key should NEVER leave the air-gapped system

set -e

echo "╔════════════════════════════════════════════════════════════╗"
echo "║  Air-Gap Arbiter - Keypair Generation                     ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Warning for online systems
if ping -c 1 -W 1 8.8.8.8 &> /dev/null; then
    echo -e "${RED}⚠ WARNING: Network connection detected!${NC}"
    echo ""
    echo "This script should ONLY be run on an air-gapped machine."
    echo "Running on a networked machine defeats the security model."
    echo ""
    read -p "Are you SURE you want to continue? (yes/NO): " CONFIRM
    if [ "$CONFIRM" != "yes" ]; then
        echo "Aborted. Run this on an offline Tails USB."
        exit 1
    fi
    echo ""
fi

# Check for required tools
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}ERROR: python3 not found${NC}"
    echo "Install: sudo apt install python3"
    exit 1
fi

# Create keypair using Python (available on Tails)
echo "Generating Ed25519 keypair..."
echo ""

python3 - <<'EOF'
import os
import binascii

try:
    from nacl.signing import SigningKey
    from nacl.encoding import HexEncoder
except ImportError:
    print("ERROR: PyNaCl not installed")
    print("Install with: pip3 install PyNaCl")
    exit(1)

# Generate new signing key
signing_key = SigningKey.generate()
verify_key = signing_key.verify_key

# Export keys as hex
private_key_hex = signing_key.encode(encoder=HexEncoder).decode('utf-8')
public_key_hex = verify_key.encode(encoder=HexEncoder).decode('utf-8')

print("=" * 60)
print("ARBITER KEYPAIR GENERATED")
print("=" * 60)
print("")
print("Public Key (hex):")
print(public_key_hex)
print("")
print("Private Key (hex) - KEEP SECRET:")
print(private_key_hex)
print("")
print("=" * 60)
print("")
print("IMPORTANT INSTRUCTIONS:")
print("")
print("1. COPY THE PUBLIC KEY to the server's .env file:")
print(f"   ARBITER_PUBKEY={public_key_hex}")
print("")
print("2. COPY THE PRIVATE KEY to arbiter-offline-review.sh:")
print("   (Edit line ~50: ARBITER_PRIVATE_KEY)")
print("")
print("3. DESTROY THIS TERMINAL OUTPUT after copying:")
print("   - Close this terminal window")
print("   - Do NOT save to disk on networked machine")
print("   - On Tails, keys vanish after reboot (amnesia)")
print("")
print("4. TEST THE KEYPAIR:")
print("   echo 'test message' | python3 -c \"")
print("   from nacl.signing import SigningKey")
print(f"   sk = SigningKey('{private_key_hex}', encoder=nacl.encoding.HexEncoder)")
print("   print(sk.sign(b'test message').signature.hex())")
print("   \"")
print("")
print("=" * 60)

# Optionally save to file (ONLY on air-gapped machine)
save = input("\nSave keys to file? (Only on AIR-GAPPED machine) [yes/NO]: ")
if save.lower() == "yes":
    with open("arbiter_keypair.txt", "w") as f:
        f.write(f"Public Key: {public_key_hex}\n")
        f.write(f"Private Key: {private_key_hex}\n")
    print(f"\n✓ Keys saved to arbiter_keypair.txt")
    print("  Remember to SHRED this file after copying:")
    print("  shred -vfz -n 7 arbiter_keypair.txt")
else:
    print("\nKeys NOT saved to disk (good for OPSEC).")

EOF

echo ""
echo -e "${GREEN}✓ Keypair generation complete${NC}"
echo ""
echo "Next steps:"
echo "  1. Add ARBITER_PUBKEY to server .env"
echo "  2. Test signature verification"
echo "  3. Shred this output/file"
echo ""
