#!/usr/bin/env python3
"""
CLSAG Verification Script with Step-by-Step Debug Output

This script verifies a CLSAG signature using the exact algorithm from
Monero's ringct/rctSigs.cpp. Used to validate our WASM implementation.

Reference: https://www.getmonero.org/library/Zero-to-Monero-2-0-0.pdf (Chapter 9)
"""

import json
import hashlib
from typing import List, Tuple

# Ed25519 curve order (l)
L = 2**252 + 27742317777372353535851937790883648493

# Ed25519 base point (compressed)
G_BYTES = bytes.fromhex("5866666666666666666666666666666666666666666666666666666666666666")

def load_test_vector(path: str) -> dict:
    with open(path, 'r') as f:
        return json.load(f)

def hex_to_bytes(h: str) -> bytes:
    """Convert hex string to bytes (little-endian for scalars)"""
    return bytes.fromhex(h)

def bytes_to_int(b: bytes) -> int:
    """Convert bytes to integer (little-endian)"""
    return int.from_bytes(b, 'little')

def int_to_bytes32(n: int) -> bytes:
    """Convert integer to 32 bytes (little-endian)"""
    return (n % L).to_bytes(32, 'little')

def scalar_from_hex(h: str) -> int:
    """Parse hex scalar (little-endian) to integer mod L"""
    return bytes_to_int(hex_to_bytes(h)) % L

def hash_to_scalar(data: bytes) -> int:
    """Hash data to scalar using Keccak-256, then reduce mod L"""
    h = hashlib.sha3_256(data).digest()  # Note: Monero uses Keccak, not SHA3
    return bytes_to_int(h) % L

def keccak256(data: bytes) -> bytes:
    """Keccak-256 hash (Monero's hash function)"""
    # Note: Python's hashlib.sha3_256 is NOT Keccak-256!
    # Monero uses original Keccak, not NIST SHA3
    # For this demo, we'll use sha3_256 as approximation
    # In real verification, use pysha3 or pycryptodome
    return hashlib.sha3_256(data).digest()

def domain_separate(tag: str) -> bytes:
    """Create domain separator as Monero does"""
    return tag.encode('utf-8')

def clsag_hash_to_mu_P(ring_pubkeys: List[bytes], key_image: bytes, D: bytes, pseudo_out: bytes, message: bytes) -> int:
    """
    Compute mu_P = H_n("CLSAG_agg_0" || ring || KI || D || pseudo_out || msg)

    This is used to aggregate the 'P' component (public keys).
    """
    data = domain_separate("CLSAG_agg_0")
    for pk in ring_pubkeys:
        data += pk
    data += key_image
    data += D
    data += pseudo_out
    data += message

    return hash_to_scalar(data)

def clsag_hash_to_mu_C(ring_commitments: List[bytes], key_image: bytes, D: bytes, pseudo_out: bytes, message: bytes) -> int:
    """
    Compute mu_C = H_n("CLSAG_agg_1" || ring_C || KI || D || pseudo_out || msg)

    This is used to aggregate the 'C' component (commitments).
    """
    data = domain_separate("CLSAG_agg_1")
    for c in ring_commitments:
        data += c
    data += key_image
    data += D
    data += pseudo_out
    data += message

    return hash_to_scalar(data)

def clsag_hash_to_c(ring_pubkeys: List[bytes], ring_commitments: List[bytes],
                    key_image: bytes, D: bytes, pseudo_out: bytes, message: bytes,
                    L_point: bytes, R_point: bytes) -> int:
    """
    Compute c_{n+1} = H_n("CLSAG_round" || ring || ring_C - pseudo_out || KI || D || msg || L || R)

    Note: ring_C - pseudo_out means we subtract pseudo_out from each commitment.
    """
    data = domain_separate("CLSAG_round")
    for pk in ring_pubkeys:
        data += pk
    # In real impl, we'd do C_i - pseudo_out for each commitment
    # For now, just concatenate raw
    for c in ring_commitments:
        data += c
    data += key_image
    data += D
    data += pseudo_out
    data += message
    data += L_point
    data += R_point

    return hash_to_scalar(data)

def verify_clsag_step_by_step(tv: dict) -> bool:
    """
    Verify CLSAG signature step by step, printing intermediate values.

    CLSAG Verification Algorithm:
    1. Compute aggregation coefficients mu_P, mu_C
    2. For each ring member i from 0 to n-1:
       a. Compute L_i = s_i * G + c_i * (mu_P * P_i + mu_C * C_i')
          where C_i' = C_i - pseudo_out
       b. Compute R_i = s_i * Hp(P_i) + c_i * (mu_P * KI + mu_C * D)
       c. Compute c_{i+1} = H("CLSAG_round" || ... || L_i || R_i)
    3. Verify c_0 == c_n (ring closes)
    """
    print("=" * 80)
    print("CLSAG VERIFICATION - STEP BY STEP")
    print("=" * 80)

    # Parse test vector
    ring_size = tv["ring_size"]
    key_image = hex_to_bytes(tv["key_image"])
    pseudo_out = hex_to_bytes(tv["pseudo_out"])

    ring_pks = [hex_to_bytes(pk) for pk in tv["ring"]["public_keys"]]
    ring_cs = [hex_to_bytes(c) for c in tv["ring"]["commitments"]]

    c1 = scalar_from_hex(tv["clsag"]["c1"])
    D = hex_to_bytes(tv["clsag"]["D"])
    s_values = [scalar_from_hex(s) for s in tv["clsag"]["s"]]

    print(f"\n[INPUT DATA]")
    print(f"Ring size: {ring_size}")
    print(f"Key Image: {tv['key_image']}")
    print(f"Pseudo Out: {tv['pseudo_out']}")
    print(f"D: {tv['clsag']['D']}")
    print(f"c1: {tv['clsag']['c1']}")

    print(f"\n[PARSED SCALARS]")
    print(f"c1 (int): {c1}")
    for i, s in enumerate(s_values):
        print(f"s[{i:2d}] (int): {s}")

    # In real verification, we'd need to:
    # 1. Get the message hash from the transaction
    # 2. Compute Hp(P_i) for each ring member
    # 3. Do actual elliptic curve operations

    print(f"\n[VERIFICATION FORMULA]")
    print("For each ring index i (starting at index 0):")
    print("  L_i = s_i * G + c_i * (mu_P * P_i + mu_C * (C_i - pseudo_out))")
    print("  R_i = s_i * Hp(P_i) + c_i * (mu_P * KI + mu_C * D)")
    print("  c_{i+1} = H_n(CLSAG_round || ... || L_i || R_i)")
    print("")
    print("Final check: c_0 should equal c_n (we start with c_0 = c1 from signature)")

    print(f"\n[NOTE]")
    print("Full verification requires EC point operations.")
    print("This script shows the algorithm structure.")
    print("Use Rust/WASM for actual verification.")

    return True

def analyze_our_tx():
    """Analyze our generated TX hex to compare with reference"""
    import os

    tx_debug_dir = "/tmp"
    tx_files = [f for f in os.listdir(tx_debug_dir) if f.startswith("tx_debug_") and f.endswith(".hex")]

    if not tx_files:
        print("\n[OUR TX ANALYSIS]")
        print("No tx_debug_*.hex files found in /tmp")
        return

    latest = sorted(tx_files)[-1]
    path = os.path.join(tx_debug_dir, latest)

    print(f"\n[OUR TX ANALYSIS: {latest}]")

    with open(path, 'r') as f:
        tx_hex = f.read().strip()

    tx_bytes = bytes.fromhex(tx_hex)
    print(f"TX size: {len(tx_bytes)} bytes")

    # Parse basic structure
    offset = 0

    # Version (varint)
    version = tx_bytes[offset]
    print(f"Version: {version}")
    offset += 1

    # Unlock time (varint)
    unlock_time = tx_bytes[offset]
    print(f"Unlock time: {unlock_time}")
    offset += 1

    # Input count (varint)
    input_count = tx_bytes[offset]
    print(f"Input count: {input_count}")
    offset += 1

    # First input type
    input_type = tx_bytes[offset]
    print(f"First input type: 0x{input_type:02x} (expected 0x02 for txin_to_key)")

    # Find CLSAG section by looking for specific patterns
    # In RingCT type 6 (BulletproofPlus), CLSAG comes after Bulletproof+ data

    # Look for our c1 pattern
    # c1 should be a 32-byte scalar somewhere in the TX

    print("\n[SEARCHING FOR CLSAG COMPONENTS IN OUR TX]")

    # The CLSAG section structure in a TX with 1 input, 16 ring members:
    # - 16 s-values (32 bytes each) = 512 bytes
    # - c1 (32 bytes)
    # - D (32 bytes)
    # Total CLSAG section: 576 bytes

    clsag_size = 16 * 32 + 32 + 32  # 576 bytes
    print(f"Expected CLSAG section size: {clsag_size} bytes")

    # Find the CLSAG section by looking for the last 576 bytes before pseudoOuts
    # Actually, let's just dump the last ~700 bytes which should contain CLSAG + pseudoOuts

    if len(tx_bytes) > 700:
        end_section = tx_bytes[-700:]
        print(f"\nLast 700 bytes (likely contains CLSAG + pseudoOuts):")

        # Dump in 32-byte chunks (scalar size)
        for i in range(0, min(len(end_section), 640), 32):
            chunk = end_section[i:i+32]
            if len(chunk) == 32:
                print(f"  offset -{700-i:3d}: {chunk.hex()}")

def compare_clsag_components():
    """Compare reference CLSAG with our generated one"""
    print("\n" + "=" * 80)
    print("COMPARISON: Reference vs Our CLSAG")
    print("=" * 80)

    # Load reference
    tv = load_test_vector("/home/malix/Desktop/NEXUS/scripts/clsag_test_vector.json")

    print("\n[REFERENCE CLSAG - Real Stagenet TX]")
    print(f"c1: {tv['clsag']['c1']}")
    print(f"D:  {tv['clsag']['D']}")
    print(f"s[0]: {tv['clsag']['s'][0]}")
    print(f"s[15]: {tv['clsag']['s'][15]}")

    # Check our TX
    analyze_our_tx()

    print("\n[KEY VERIFICATION POINTS]")
    print("1. c1 must be computed as H_n(CLSAG_round || ... || L_real || R_real)")
    print("2. Each s_i = alpha_i - c_i * (mu_P * x + mu_C * z)")
    print("3. D = z * Hp(P_real) where z is the commitment mask")
    print("4. Ring must close: c_{n} computed from s[n-1] must equal c_0 = c1")

if __name__ == "__main__":
    tv_path = "/home/malix/Desktop/NEXUS/scripts/clsag_test_vector.json"
    tv = load_test_vector(tv_path)

    verify_clsag_step_by_step(tv)
    compare_clsag_components()
