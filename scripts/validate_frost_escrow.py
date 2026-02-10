#!/usr/bin/env python3
"""
FROST Escrow Validation Script

Validates the cryptographic correctness of FROST DKG outputs and signing flow.
Uses known values to compute expected outputs and compare with actual values.

Escrow: ef57f177-f873-40c3-a175-4ab87c195ad8
"""

import hashlib
import base64
from typing import Tuple

# ===== KNOWN VALUES FROM ESCROW =====

ESCROW_ID = "ef57f177-f873-40c3-a175-4ab87c195ad8"

# Transaction data
TX_ID = "2cfe655d56c881908a883a8bb8f0f85bc09310cf7f43816bc2fd3801088ba665"
TX_KEY = "54d48a7b6f680a88fd04b4cf56b18f09e01c66ab3aa5ec9aabb33a258de43704"
SENDER_ADDRESS = "5B8Wc19s2LFZQ914VxuLMsbrSUdBiuHqD7QWvqpAC6cxL4G3TVsP12M9n5eYhZXk69EbEDMzqSBs7hqvQzNgqUvxRgdpedp"
ESCROW_ADDRESS = "57HRDdV2XrAVJFnChTRsbDT1h5Lv2fxpSiZxgGhxKCP8h1gGfrS6YJvgeGpLixGsruAZphkpZc5mPNHh94w1QVRxTjRZ4tu"

# From DB
DB_FROST_GROUP_PUBKEY = "8fe544aed04ac3a92dff7d2fb076689b83db5d8eba175bf8853e123b2f0e0fef"
DB_MULTISIG_ADDRESS = "57HRDdV2XrAVJFnChTRsbDT1h5Lv2fxpSiZxgGhxKCP8h1gGfrS6YJvgeGpLixGsruAZphkpZc5mPNHh94w1QVRxTjRZ4tu"
DB_VIEW_KEY = "f2fcd78c14a49e707e4a7f4dfc24f5cfbfddfff5f94837bcddd72d88d963e808"

# From localStorage - VENDOR
VENDOR_SECRET_SHARE = "7dfcdfcaafbe5b7abbb69237954839f30172c31d91bbfe57357542bfd504b60e"
VENDOR_VERIFYING_SHARE = "f312939afe2d842860804e24a0a1680124052679c0f96f070bf942017ff2caf7"
VENDOR_GROUP_PUBKEY = "8fe544aed04ac3a92dff7d2fb076689b83db5d8eba175bf8853e123b2f0e0fef"

# From localStorage - BUYER
BUYER_SECRET_SHARE = "916e1d306297b252a49d616846bc1e22276ea3d535280bdde3f8d8123541b70b"

# Lagrange coefficients for buyer(1) + vendor(2) pair
# λ_buyer = j/(j-i) = 2/(2-1) = 2
# λ_vendor = i/(i-j) = 1/(1-2) = -1 (mod l)
# In scalar form (mod curve order l):
# l = 2^252 + 27742317777372353535851937790883648493
L = 2**252 + 27742317777372353535851937790883648493
LAMBDA_BUYER = 2
LAMBDA_VENDOR = L - 1  # -1 mod l

# ===== HELPER FUNCTIONS =====

def hex_to_bytes(h: str) -> bytes:
    return bytes.fromhex(h)

def bytes_to_hex(b: bytes) -> str:
    return b.hex()

def scalar_to_bytes(s: int) -> bytes:
    """Convert scalar to 32-byte little-endian representation"""
    return (s % L).to_bytes(32, 'little')

def bytes_to_scalar(b: bytes) -> int:
    """Convert 32-byte little-endian to scalar"""
    return int.from_bytes(b, 'little')

def reduce_scalar(s: int) -> int:
    """Reduce scalar mod L"""
    return s % L

def decode_base64(s: str) -> str:
    """Decode base64 to hex string"""
    return base64.b64decode(s).decode('utf-8')

# ===== MONERO ADDRESS FUNCTIONS =====

# Base58 alphabet (Monero uses different from standard)
MONERO_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

def base58_decode(s: str) -> bytes:
    """Decode Monero base58 string to bytes"""
    result = 0
    for c in s:
        result = result * 58 + MONERO_ALPHABET.index(c)

    # Convert to bytes (variable length based on input)
    hex_str = hex(result)[2:]
    if len(hex_str) % 2:
        hex_str = '0' + hex_str
    return bytes.fromhex(hex_str)

def base58_encode(data: bytes) -> str:
    """Encode bytes to Monero base58 string"""
    n = int.from_bytes(data, 'big')
    result = []
    while n > 0:
        n, r = divmod(n, 58)
        result.append(MONERO_ALPHABET[r])
    return ''.join(reversed(result))

def keccak256(data: bytes) -> bytes:
    """Keccak-256 hash (used in Monero)"""
    from Crypto.Hash import keccak
    k = keccak.new(digest_bits=256)
    k.update(data)
    return k.digest()

def parse_monero_address(address: str) -> Tuple[bytes, bytes, bytes]:
    """Parse Monero address to (network_byte, spend_pubkey, view_pubkey)"""
    # Monero addresses are 95 chars for standard, 106 for integrated
    if len(address) == 95:
        # Standard address
        # Structure: 1 byte network + 32 bytes spend + 32 bytes view + 4 bytes checksum
        decoded = base58_decode(address)
        # This is tricky because Monero uses special block-based encoding
        # For now, let's use a simpler approach
        pass

    # For validation, we'll compare the address prefix
    return None, None, None

# ===== VALIDATION FUNCTIONS =====

def validate_group_pubkey():
    """Check that group_pubkey from vendor matches DB"""
    print("\n=== STEP 1: Validate group_pubkey consistency ===")
    print(f"Vendor localStorage: {VENDOR_GROUP_PUBKEY}")
    print(f"DB frost_group_pubkey: {DB_FROST_GROUP_PUBKEY}")

    if VENDOR_GROUP_PUBKEY == DB_FROST_GROUP_PUBKEY:
        print("✅ group_pubkey MATCHES")
        return True
    else:
        print("❌ group_pubkey MISMATCH!")
        return False

def validate_address():
    """Check that multisig_address matches escrow destination"""
    print("\n=== STEP 2: Validate escrow address ===")
    print(f"TX sender address:   {SENDER_ADDRESS}")
    print(f"TX destination:      {ESCROW_ADDRESS}")
    print(f"DB multisig_address: {DB_MULTISIG_ADDRESS}")

    if DB_MULTISIG_ADDRESS == ESCROW_ADDRESS:
        print("✅ DB address matches TX destination (escrow funded correctly)")
        return True
    else:
        print("❌ Address mismatch!")
        return False

def validate_lagrange_coefficients():
    """Validate Lagrange coefficient computation"""
    print("\n=== STEP 3: Validate Lagrange coefficients ===")

    # For buyer(index=1) + vendor(index=2) pair:
    # λ_i = Π_{j≠i} j/(j-i)
    # λ_buyer (i=1): 2/(2-1) = 2
    # λ_vendor (i=2): 1/(1-2) = -1 mod L

    print(f"Buyer index: 1, Vendor index: 2")
    print(f"λ_buyer = 2/(2-1) = 2")
    print(f"λ_vendor = 1/(1-2) = -1 mod L")

    # In hex (little-endian 32 bytes):
    lambda_buyer_hex = bytes_to_hex(scalar_to_bytes(LAMBDA_BUYER))
    lambda_vendor_hex = bytes_to_hex(scalar_to_bytes(LAMBDA_VENDOR))

    print(f"\nλ_buyer (hex LE): {lambda_buyer_hex[:32]}...")
    print(f"λ_vendor (hex LE): {lambda_vendor_hex[:32]}...")

    # Expected values from WASM (should match):
    # λ_buyer = 0200000000000000...00
    # λ_vendor = ecd3f55c1a631258... (L-1 in little-endian)

    expected_buyer = "0200000000000000000000000000000000000000000000000000000000000000"
    expected_vendor_prefix = "ecd3f55c1a631258"  # From logs

    if lambda_buyer_hex == expected_buyer:
        print(f"✅ λ_buyer matches expected")
    else:
        print(f"❌ λ_buyer mismatch!")

    if lambda_vendor_hex.startswith(expected_vendor_prefix):
        print(f"✅ λ_vendor prefix matches expected")
    else:
        print(f"❌ λ_vendor prefix mismatch!")
        print(f"   Expected prefix: {expected_vendor_prefix}")
        print(f"   Got: {lambda_vendor_hex[:16]}")

def validate_secret_share():
    """Validate that vendor's secret share is a valid scalar"""
    print("\n=== STEP 4: Validate secret shares ===")
    print(f"Vendor share: {VENDOR_SECRET_SHARE}")
    print(f"Buyer share:  {BUYER_SECRET_SHARE}")

    vendor_int = bytes_to_scalar(hex_to_bytes(VENDOR_SECRET_SHARE))
    buyer_int = bytes_to_scalar(hex_to_bytes(BUYER_SECRET_SHARE))

    print(f"\nVendor as int: {vendor_int}")
    print(f"Buyer as int:  {buyer_int}")

    all_valid = True
    for name, val in [("Vendor", vendor_int), ("Buyer", buyer_int)]:
        if val < L and val > 0:
            print(f"✅ {name} share is valid scalar (0 < x < L)")
        else:
            print(f"❌ {name} share is invalid!")
            all_valid = False

    return all_valid

def validate_lagrange_reconstruction():
    """Validate that Lagrange reconstruction gives correct group secret"""
    print("\n=== STEP 5: Validate Lagrange reconstruction ===")

    vendor_int = bytes_to_scalar(hex_to_bytes(VENDOR_SECRET_SHARE))
    buyer_int = bytes_to_scalar(hex_to_bytes(BUYER_SECRET_SHARE))

    # Lagrange reconstruction: group_secret = λ_buyer * buyer + λ_vendor * vendor
    # For buyer(1) + vendor(2): λ_buyer = 2, λ_vendor = -1
    lambda_buyer = 2
    lambda_vendor = L - 1  # -1 mod L

    # Compute contributions
    buyer_contrib = (lambda_buyer * buyer_int) % L
    vendor_contrib = (lambda_vendor * vendor_int) % L

    # Reconstructed group secret
    group_secret = (buyer_contrib + vendor_contrib) % L

    print(f"λ_buyer * buyer_share  = {buyer_contrib}")
    print(f"λ_vendor * vendor_share = {vendor_contrib}")
    print(f"group_secret (sum mod L) = {group_secret}")
    print(f"\ngroup_secret hex (LE): {bytes_to_hex(scalar_to_bytes(group_secret))}")

    # To verify: group_secret * G should equal group_pubkey
    # We can't do EC multiplication in pure Python without a library,
    # but we can at least check the scalar is valid
    print(f"\n⚠️  To fully verify: group_secret * G should equal group_pubkey")
    print(f"   group_pubkey: {DB_FROST_GROUP_PUBKEY}")
    print(f"\n   Use WASM or Rust to verify: scalar_mult_base(group_secret) == group_pubkey")

    return group_secret

def print_summary():
    """Print test data summary for manual verification"""
    print("\n" + "="*60)
    print("FROST ESCROW VALIDATION SUMMARY")
    print("="*60)
    print(f"\nEscrow ID: {ESCROW_ID}")
    print(f"\nTransaction:")
    print(f"  TX ID: {TX_ID}")
    print(f"  TX Key: {TX_KEY}")
    print(f"  Amount: 0.001 XMR")
    print(f"\nAddresses:")
    print(f"  Sender (funder):   {SENDER_ADDRESS}")
    print(f"  Escrow (FROST):    {ESCROW_ADDRESS}")
    print(f"  DB multisig_addr:  {DB_MULTISIG_ADDRESS}")
    print(f"\nFROST Keys:")
    print(f"  group_pubkey: {DB_FROST_GROUP_PUBKEY}")
    print(f"  view_key:     {DB_VIEW_KEY}")
    print(f"  vendor_share: {VENDOR_SECRET_SHARE}")
    print(f"  buyer_share:  {BUYER_SECRET_SHARE}")
    print(f"\nLagrange (buyer+vendor):")
    print(f"  λ_buyer:  2 (0x{bytes_to_hex(scalar_to_bytes(2))[:16]}...)")
    print(f"  λ_vendor: -1 mod L (0x{bytes_to_hex(scalar_to_bytes(L-1))[:16]}...)")

def main():
    print("FROST Escrow Validation Script")
    print("="*60)

    print_summary()

    validate_group_pubkey()
    validate_address()
    validate_lagrange_coefficients()
    validate_secret_share()
    validate_lagrange_reconstruction()

    print("\n" + "="*60)
    print("NEXT STEPS:")
    print("="*60)
    print("""
1. COLLECT BUYER DATA:
   Need buyer's frost_secret_share for full validation

2. VERIFY LAGRANGE x SHARE COMPUTATION:
   vendor_contrib = λ_vendor * vendor_share
   buyer_contrib = λ_buyer * buyer_share

3. VERIFY KEY IMAGE:
   x_eff = d + λ_vendor*s_vendor (first signer includes derivation)
   KI = x_eff * Hp(one_time_pubkey)

4. RUN SIGNING TEST:
   Once 10 confirmations done, test full flow
""")

if __name__ == "__main__":
    main()
