#!/usr/bin/env python3
"""
Monero Transaction Parser

Parses raw Monero transaction bytes to extract and analyze CLSAG components.
Used for comparing our generated transactions against known-good ones.
"""

import sys
import os
from typing import Tuple, List, Dict, Any

def read_varint(data: bytes, offset: int) -> Tuple[int, int]:
    """Read a varint from data at offset. Returns (value, new_offset)."""
    result = 0
    shift = 0
    while True:
        if offset >= len(data):
            raise ValueError(f"Unexpected end of data reading varint at offset {offset}")
        byte = data[offset]
        result |= (byte & 0x7f) << shift
        offset += 1
        if byte & 0x80 == 0:
            break
        shift += 7
    return result, offset

def read_bytes(data: bytes, offset: int, count: int) -> Tuple[bytes, int]:
    """Read count bytes from data at offset. Returns (bytes, new_offset)."""
    if offset + count > len(data):
        raise ValueError(f"Unexpected end of data at offset {offset}, need {count} bytes")
    return data[offset:offset+count], offset + count

def parse_txin_to_key(data: bytes, offset: int) -> Tuple[Dict, int]:
    """Parse a txin_to_key input."""
    result = {}

    # amount (varint, always 0 for RingCT)
    result['amount'], offset = read_varint(data, offset)

    # key_offsets count (varint)
    key_offset_count, offset = read_varint(data, offset)
    result['ring_size'] = key_offset_count

    # key_offsets (relative offsets)
    result['key_offsets'] = []
    for _ in range(key_offset_count):
        ko, offset = read_varint(data, offset)
        result['key_offsets'].append(ko)

    # key_image (32 bytes)
    result['key_image'], offset = read_bytes(data, offset, 32)

    return result, offset

def parse_txout_to_tagged_key(data: bytes, offset: int) -> Tuple[Dict, int]:
    """Parse a txout_to_tagged_key output (type 0x03)."""
    result = {}

    # public_key (32 bytes)
    result['public_key'], offset = read_bytes(data, offset, 32)

    # view_tag (1 byte)
    result['view_tag'], offset = read_bytes(data, offset, 1)

    return result, offset

def parse_txout_to_key(data: bytes, offset: int) -> Tuple[Dict, int]:
    """Parse a txout_to_key output (type 0x02)."""
    result = {}

    # public_key (32 bytes)
    result['public_key'], offset = read_bytes(data, offset, 32)

    return result, offset

def parse_tx_prefix(data: bytes, offset: int = 0) -> Tuple[Dict, int]:
    """Parse transaction prefix (up to and including extra field)."""
    result = {}

    # version (varint)
    result['version'], offset = read_varint(data, offset)
    print(f"  Version: {result['version']}")

    # unlock_time (varint)
    result['unlock_time'], offset = read_varint(data, offset)
    print(f"  Unlock time: {result['unlock_time']}")

    # vin count (varint)
    vin_count, offset = read_varint(data, offset)
    result['vin_count'] = vin_count
    print(f"  Input count: {vin_count}")

    result['vin'] = []
    for i in range(vin_count):
        input_type = data[offset]
        offset += 1

        if input_type == 0x02:  # txin_to_key
            print(f"  Input {i}: txin_to_key (0x02)")
            inp, offset = parse_txin_to_key(data, offset)
            inp['type'] = 'txin_to_key'
            result['vin'].append(inp)
            print(f"    Ring size: {inp['ring_size']}")
            print(f"    Key image: {inp['key_image'].hex()}")
        else:
            raise ValueError(f"Unsupported input type: 0x{input_type:02x}")

    # vout count (varint)
    vout_count, offset = read_varint(data, offset)
    result['vout_count'] = vout_count
    print(f"  Output count: {vout_count}")

    result['vout'] = []
    for i in range(vout_count):
        out = {}

        # amount (varint, always 0 for RingCT)
        out['amount'], offset = read_varint(data, offset)

        # output type
        output_type = data[offset]
        offset += 1

        if output_type == 0x03:  # txout_to_tagged_key
            print(f"  Output {i}: txout_to_tagged_key (0x03) ✓")
            target, offset = parse_txout_to_tagged_key(data, offset)
            out['target'] = target
            out['type'] = 'tagged_key'
            print(f"    Public key: {target['public_key'].hex()}")
            print(f"    View tag: {target['view_tag'].hex()}")
        elif output_type == 0x02:  # txout_to_key (old format!)
            print(f"  Output {i}: txout_to_key (0x02) ⚠️ OLD FORMAT!")
            target, offset = parse_txout_to_key(data, offset)
            out['target'] = target
            out['type'] = 'key'
            print(f"    Public key: {target['public_key'].hex()}")
        else:
            raise ValueError(f"Unsupported output type: 0x{output_type:02x}")

        result['vout'].append(out)

    # extra field (variable length)
    extra_len, offset = read_varint(data, offset)
    result['extra'], offset = read_bytes(data, offset, extra_len)
    print(f"  Extra length: {extra_len}")

    return result, offset

def parse_rct_signatures(data: bytes, offset: int, num_inputs: int, num_outputs: int) -> Tuple[Dict, int]:
    """Parse RCT signatures (rct_signatures field)."""
    result = {}

    # type (1 byte)
    result['type'] = data[offset]
    offset += 1
    print(f"  RCT type: {result['type']} ({'BulletproofPlus' if result['type'] == 6 else 'Unknown'})")

    if result['type'] == 0:
        return result, offset  # No RCT

    # txnFee (varint)
    result['txnFee'], offset = read_varint(data, offset)
    print(f"  Fee: {result['txnFee']} atomic units ({result['txnFee'] / 1e12:.12f} XMR)")

    # ecdhInfo (for each output)
    result['ecdhInfo'] = []
    for i in range(num_outputs):
        if result['type'] >= 4:  # Compact ecdhInfo for BP/BP+
            ecdh, offset = read_bytes(data, offset, 8)
        else:
            ecdh, offset = read_bytes(data, offset, 64)
        result['ecdhInfo'].append(ecdh)
    print(f"  ecdhInfo count: {len(result['ecdhInfo'])}")

    # outPk (commitment for each output, 32 bytes each)
    result['outPk'] = []
    for i in range(num_outputs):
        pk, offset = read_bytes(data, offset, 32)
        result['outPk'].append(pk)
        print(f"  outPk[{i}]: {pk.hex()}")

    return result, offset

def parse_bulletproof_plus(data: bytes, offset: int) -> Tuple[Dict, int]:
    """Parse BulletproofPlus data."""
    result = {}

    # Number of BP+ proofs (varint)
    bp_count, offset = read_varint(data, offset)
    result['count'] = bp_count
    print(f"    BP+ proof count: {bp_count}")

    result['proofs'] = []
    for i in range(bp_count):
        proof = {}

        # A (32 bytes)
        proof['A'], offset = read_bytes(data, offset, 32)

        # A1 (32 bytes)
        proof['A1'], offset = read_bytes(data, offset, 32)

        # B (32 bytes)
        proof['B'], offset = read_bytes(data, offset, 32)

        # r1 (32 bytes)
        proof['r1'], offset = read_bytes(data, offset, 32)

        # s1 (32 bytes)
        proof['s1'], offset = read_bytes(data, offset, 32)

        # d1 (32 bytes)
        proof['d1'], offset = read_bytes(data, offset, 32)

        # L count (varint)
        L_count, offset = read_varint(data, offset)
        proof['L'] = []
        for _ in range(L_count):
            L, offset = read_bytes(data, offset, 32)
            proof['L'].append(L)

        # R count (varint)
        R_count, offset = read_varint(data, offset)
        proof['R'] = []
        for _ in range(R_count):
            R, offset = read_bytes(data, offset, 32)
            proof['R'].append(R)

        print(f"    BP+ proof {i}: L/R count = {L_count}/{R_count}")
        result['proofs'].append(proof)

    return result, offset

def parse_clsag(data: bytes, offset: int, ring_size: int) -> Tuple[Dict, int]:
    """Parse a single CLSAG signature."""
    result = {}

    # s values (ring_size * 32 bytes)
    result['s'] = []
    for i in range(ring_size):
        s, offset = read_bytes(data, offset, 32)
        result['s'].append(s)
        if i < 3 or i >= ring_size - 1:
            print(f"      s[{i:2d}]: {s.hex()}")
        elif i == 3:
            print(f"      ... ({ring_size - 4} more s values) ...")

    # c1 (32 bytes)
    result['c1'], offset = read_bytes(data, offset, 32)
    print(f"      c1: {result['c1'].hex()}")

    # D (32 bytes)
    result['D'], offset = read_bytes(data, offset, 32)
    print(f"      D:  {result['D'].hex()}")

    return result, offset

def parse_rctsig_prunable(data: bytes, offset: int, num_inputs: int, ring_size: int) -> Tuple[Dict, int]:
    """Parse rctsig_prunable (BP+ and CLSAG data)."""
    result = {}
    print(f"\n[RCT PRUNABLE at offset {offset}]")

    # BulletproofPlus
    result['bp_plus'], offset = parse_bulletproof_plus(data, offset)

    # CLSAGs (one per input)
    print(f"\n  [CLSAG SIGNATURES]")
    result['CLSAGs'] = []
    for i in range(num_inputs):
        print(f"    CLSAG {i} (ring size {ring_size}):")
        clsag, offset = parse_clsag(data, offset, ring_size)
        result['CLSAGs'].append(clsag)

    # pseudoOuts (one 32-byte commitment per input)
    result['pseudoOuts'] = []
    print(f"\n  [PSEUDO OUTPUTS]")
    for i in range(num_inputs):
        po, offset = read_bytes(data, offset, 32)
        result['pseudoOuts'].append(po)
        print(f"    pseudoOut[{i}]: {po.hex()}")

    return result, offset

def parse_transaction(data: bytes) -> Dict:
    """Parse a complete Monero transaction."""
    result = {}
    print("=" * 80)
    print(f"PARSING MONERO TRANSACTION ({len(data)} bytes)")
    print("=" * 80)

    offset = 0

    # Parse prefix
    print("\n[TX PREFIX]")
    result['prefix'], offset = parse_tx_prefix(data, offset)

    # Get ring size from first input
    ring_size = result['prefix']['vin'][0]['ring_size'] if result['prefix']['vin'] else 16
    num_inputs = result['prefix']['vin_count']
    num_outputs = result['prefix']['vout_count']

    # Parse rct_signatures
    print("\n[RCT SIGNATURES]")
    result['rct_signatures'], offset = parse_rct_signatures(data, offset, num_inputs, num_outputs)

    # Parse rctsig_prunable (if RCT type > 0)
    if result['rct_signatures']['type'] > 0:
        result['rctsig_prunable'], offset = parse_rctsig_prunable(data, offset, num_inputs, ring_size)

    # Check if we consumed all bytes
    remaining = len(data) - offset
    if remaining > 0:
        print(f"\n⚠️ WARNING: {remaining} bytes remaining after parsing!")
        print(f"Remaining bytes: {data[offset:].hex()}")
    else:
        print(f"\n✅ All bytes consumed. Transaction parsed successfully.")

    return result

def compare_with_reference():
    """Compare our TX with the reference stagenet TX."""
    # Load reference
    import json
    with open("/home/malix/Desktop/NEXUS/scripts/clsag_test_vector.json") as f:
        ref = json.load(f)

    print("\n" + "=" * 80)
    print("REFERENCE CLSAG (Real Stagenet TX)")
    print("=" * 80)
    print(f"Key Image: {ref['key_image']}")
    print(f"c1: {ref['clsag']['c1']}")
    print(f"D:  {ref['clsag']['D']}")
    print(f"s[0]: {ref['clsag']['s'][0]}")
    print(f"pseudoOut: {ref['pseudo_out']}")

def main():
    # Find latest tx_debug file
    tx_dir = "/tmp"
    tx_files = sorted([f for f in os.listdir(tx_dir) if f.startswith("tx_debug_") and f.endswith(".hex")])

    if not tx_files:
        print("No tx_debug_*.hex files found in /tmp")
        print("Looking for any .hex file...")

        tx_files = sorted([f for f in os.listdir(tx_dir) if f.endswith(".hex")])
        if not tx_files:
            print("No .hex files found")
            return

    latest = tx_files[-1]
    path = os.path.join(tx_dir, latest)

    print(f"Parsing: {path}")

    with open(path, 'r') as f:
        tx_hex = f.read().strip()

    tx_bytes = bytes.fromhex(tx_hex)

    try:
        result = parse_transaction(tx_bytes)
        compare_with_reference()
    except Exception as e:
        print(f"\n❌ PARSING ERROR: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
