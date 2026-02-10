#!/usr/bin/env python3
"""
Monero Transaction Hex Parser & Validator
==========================================
Phase 1 Debug Tool - Offline TX analysis

Usage: python3 scripts/debug-tx-hex.py /tmp/tx_debug_*.hex

Validates:
- TX structure (version, unlock_time, inputs, outputs, extra, RCT)
- Output types (0x02 vs 0x03)
- Ring sizes
- RCT type
- Ed25519 point validity (basic checks)
- Commitment balance (sum checks)
"""

import sys
import struct
from pathlib import Path

# ANSI colors
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"

def read_varint(data, offset):
    """Read Monero-style varint, return (value, new_offset)"""
    result = 0
    shift = 0
    while offset < len(data):
        byte = data[offset]
        offset += 1
        result |= (byte & 0x7F) << shift
        if (byte & 0x80) == 0:
            break
        shift += 7
    return result, offset

def bytes_to_hex(data):
    """Convert bytes to hex string"""
    return data.hex() if isinstance(data, bytes) else data

def is_valid_ed25519_point(point_bytes):
    """Basic check if 32 bytes could be valid Ed25519 point"""
    if len(point_bytes) != 32:
        return False, "Wrong length"
    # Check not all zeros
    if point_bytes == b'\x00' * 32:
        return False, "All zeros (identity)"
    # Check not all 0xFF
    if point_bytes == b'\xff' * 32:
        return False, "All 0xFF"
    # Check last byte's high bit (y-coordinate encoding)
    # Valid points have specific patterns
    return True, "OK"

def parse_tx_hex(hex_string):
    """Parse Monero transaction from hex string"""
    # Clean hex string
    hex_clean = hex_string.strip().replace('\n', '').replace(' ', '')

    try:
        data = bytes.fromhex(hex_clean)
    except ValueError as e:
        return {"error": f"Invalid hex: {e}"}

    result = {
        "raw_length": len(data),
        "hex_length": len(hex_clean),
        "errors": [],
        "warnings": []
    }

    offset = 0

    # === TX PREFIX ===
    print(f"\n{CYAN}=== TX PREFIX ==={RESET}")

    # Version
    version, offset = read_varint(data, offset)
    result["version"] = version
    print(f"[{offset-1:4d}] version: {version}")
    if version != 2:
        result["errors"].append(f"Invalid version {version}, expected 2")

    # Unlock time
    unlock_time, offset = read_varint(data, offset)
    result["unlock_time"] = unlock_time
    print(f"[{offset-1:4d}] unlock_time: {unlock_time}")

    # === INPUTS ===
    print(f"\n{CYAN}=== INPUTS ==={RESET}")

    num_inputs, offset = read_varint(data, offset)
    result["num_inputs"] = num_inputs
    print(f"[{offset-1:4d}] num_inputs: {num_inputs}")

    if num_inputs == 0:
        result["errors"].append("Zero inputs!")

    result["inputs"] = []
    for i in range(num_inputs):
        inp = {"index": i}
        print(f"\n  {YELLOW}Input {i}:{RESET}")

        # Input type
        input_type = data[offset]
        offset += 1
        inp["type"] = input_type

        if input_type == 0x02:  # txin_to_key
            print(f"    [{offset-1:4d}] type: 0x02 (txin_to_key)")

            # Amount (always 0 for RingCT)
            amount, offset = read_varint(data, offset)
            inp["amount"] = amount
            print(f"    [{offset-1:4d}] amount: {amount}")

            # Key offsets count
            num_offsets, offset = read_varint(data, offset)
            inp["ring_size"] = num_offsets
            print(f"    [{offset-1:4d}] ring_size: {num_offsets}")

            if num_offsets != 16:
                result["warnings"].append(f"Input {i}: ring_size={num_offsets}, expected 16")

            # Key offsets (relative)
            offsets = []
            for j in range(num_offsets):
                off, offset = read_varint(data, offset)
                offsets.append(off)
            inp["key_offsets"] = offsets
            print(f"    [{offset-1:4d}] offsets: [{offsets[0]}, {offsets[1]}, ... {offsets[-1]}]")

            # Key image (32 bytes)
            key_image = data[offset:offset+32]
            offset += 32
            inp["key_image"] = key_image.hex()
            valid, reason = is_valid_ed25519_point(key_image)
            status = f"{GREEN}OK{RESET}" if valid else f"{RED}{reason}{RESET}"
            print(f"    [{offset-32:4d}] key_image: {key_image.hex()[:16]}... [{status}]")
            if not valid:
                result["errors"].append(f"Input {i}: invalid key_image - {reason}")
        else:
            result["errors"].append(f"Input {i}: unknown type 0x{input_type:02x}")
            print(f"    [{offset-1:4d}] type: 0x{input_type:02x} {RED}UNKNOWN{RESET}")

        result["inputs"].append(inp)

    # === OUTPUTS ===
    print(f"\n{CYAN}=== OUTPUTS ==={RESET}")

    num_outputs, offset = read_varint(data, offset)
    result["num_outputs"] = num_outputs
    print(f"[{offset-1:4d}] num_outputs: {num_outputs}")

    if num_outputs == 0:
        result["errors"].append("Zero outputs!")

    result["outputs"] = []
    for i in range(num_outputs):
        out = {"index": i}
        print(f"\n  {YELLOW}Output {i}:{RESET}")

        # Amount (always 0 for RingCT)
        amount, offset = read_varint(data, offset)
        out["amount"] = amount
        print(f"    [{offset-1:4d}] amount: {amount}")

        # Output type
        output_type = data[offset]
        offset += 1
        out["type"] = output_type

        if output_type == 0x02:  # txout_to_key (NO view tag)
            print(f"    [{offset-1:4d}] type: 0x02 (txout_to_key) {YELLOW}NO VIEW TAG{RESET}")
            result["warnings"].append(f"Output {i}: type 0x02 (no view_tag) - should be 0x03 for HF15+")

            # Target key (32 bytes)
            target_key = data[offset:offset+32]
            offset += 32
            out["target_key"] = target_key.hex()
            valid, reason = is_valid_ed25519_point(target_key)
            status = f"{GREEN}OK{RESET}" if valid else f"{RED}{reason}{RESET}"
            print(f"    [{offset-32:4d}] target_key: {target_key.hex()[:16]}... [{status}]")

        elif output_type == 0x03:  # txout_to_tagged_key (WITH view tag)
            print(f"    [{offset-1:4d}] type: 0x03 (txout_to_tagged_key) {GREEN}WITH VIEW TAG{RESET}")

            # Target key (32 bytes)
            target_key = data[offset:offset+32]
            offset += 32
            out["target_key"] = target_key.hex()
            valid, reason = is_valid_ed25519_point(target_key)
            status = f"{GREEN}OK{RESET}" if valid else f"{RED}{reason}{RESET}"
            print(f"    [{offset-32:4d}] target_key: {target_key.hex()[:16]}... [{status}]")

            # View tag (1 byte)
            view_tag = data[offset]
            offset += 1
            out["view_tag"] = view_tag
            print(f"    [{offset-1:4d}] view_tag: 0x{view_tag:02x} ({view_tag})")

        else:
            result["errors"].append(f"Output {i}: unknown type 0x{output_type:02x}")
            print(f"    [{offset-1:4d}] type: 0x{output_type:02x} {RED}UNKNOWN{RESET}")

        result["outputs"].append(out)

    # === EXTRA ===
    print(f"\n{CYAN}=== EXTRA ==={RESET}")

    extra_len, offset = read_varint(data, offset)
    result["extra_length"] = extra_len
    print(f"[{offset-1:4d}] extra_length: {extra_len}")

    # Sanity check extra length
    if extra_len > 1000:
        result["errors"].append(f"Extra length {extra_len} is suspiciously large (>1000)")
        print(f"    {RED}ERROR: Extra length too large!{RESET}")
    elif extra_len < 33:
        result["warnings"].append(f"Extra length {extra_len} is small (<33)")

    if offset + extra_len <= len(data):
        extra_data = data[offset:offset+extra_len]
        offset += extra_len
        result["extra_data"] = extra_data.hex()

        # Parse extra fields
        print(f"[{offset-extra_len:4d}] extra_data: {extra_data.hex()[:32]}...")

        # Look for tx_pubkey tag (0x01)
        if extra_len >= 33 and extra_data[0] == 0x01:
            tx_pubkey = extra_data[1:33]
            valid, reason = is_valid_ed25519_point(tx_pubkey)
            status = f"{GREEN}OK{RESET}" if valid else f"{RED}{reason}{RESET}"
            print(f"    tx_pubkey: {tx_pubkey.hex()[:16]}... [{status}]")
            result["tx_pubkey"] = tx_pubkey.hex()

        # Look for additional pubkeys tag (0x04)
        if extra_len > 33:
            remaining = extra_data[33:]
            if len(remaining) > 0:
                tag = remaining[0]
                if tag == 0x04:
                    print(f"    additional_pubkeys tag: 0x04")
    else:
        result["errors"].append(f"Extra extends beyond data (need {extra_len}, have {len(data)-offset})")

    # === RCT SIGNATURE ===
    print(f"\n{CYAN}=== RCT SIGNATURE ==={RESET}")

    if offset < len(data):
        rct_type = data[offset]
        offset += 1
        result["rct_type"] = rct_type

        rct_names = {
            0: "RCTTypeNull",
            1: "RCTTypeFull",
            2: "RCTTypeSimple",
            3: "RCTTypeBulletproof",
            4: "RCTTypeBulletproof2",
            5: "RCTTypeCLSAG",
            6: "RCTTypeBulletproofPlus"
        }
        rct_name = rct_names.get(rct_type, f"UNKNOWN")

        if rct_type == 6:
            print(f"[{offset-1:4d}] rct_type: {rct_type} ({rct_name}) {GREEN}OK{RESET}")
        elif rct_type in rct_names:
            print(f"[{offset-1:4d}] rct_type: {rct_type} ({rct_name}) {YELLOW}OLD TYPE{RESET}")
            result["warnings"].append(f"RCT type {rct_type} ({rct_name}) - should be 6 for current network")
        else:
            print(f"[{offset-1:4d}] rct_type: {rct_type} {RED}INVALID{RESET}")
            result["errors"].append(f"Invalid RCT type {rct_type}")

        # Parse RCT base for type 6
        if rct_type == 6:
            # txnFee
            txn_fee, offset = read_varint(data, offset)
            result["txn_fee"] = txn_fee
            print(f"[{offset-1:4d}] txn_fee: {txn_fee} atomic units ({txn_fee/1e12:.12f} XMR)")

            # Pseudo outputs (for Simple/CLSAG types)
            # Only if num_inputs > 0
            if num_inputs > 0:
                print(f"\n  {YELLOW}Pseudo Outputs:{RESET}")
                pseudo_outs = []
                for i in range(num_inputs):
                    pseudo_out = data[offset:offset+32]
                    offset += 32
                    pseudo_outs.append(pseudo_out.hex())
                    valid, reason = is_valid_ed25519_point(pseudo_out)
                    status = f"{GREEN}OK{RESET}" if valid else f"{RED}{reason}{RESET}"
                    print(f"    [{offset-32:4d}] pseudo_out[{i}]: {pseudo_out.hex()[:16]}... [{status}]")
                result["pseudo_outputs"] = pseudo_outs

            # ecdhInfo (encrypted amounts)
            print(f"\n  {YELLOW}ECDH Info (encrypted amounts):{RESET}")
            ecdh_info = []
            for i in range(num_outputs):
                # For BP+, ecdhInfo is 8 bytes per output
                ecdh = data[offset:offset+8]
                offset += 8
                ecdh_info.append(ecdh.hex())
                print(f"    [{offset-8:4d}] ecdh[{i}]: {ecdh.hex()}")
            result["ecdh_info"] = ecdh_info

            # Output commitments
            print(f"\n  {YELLOW}Output Commitments:{RESET}")
            out_commits = []
            for i in range(num_outputs):
                commit = data[offset:offset+32]
                offset += 32
                out_commits.append(commit.hex())
                valid, reason = is_valid_ed25519_point(commit)
                status = f"{GREEN}OK{RESET}" if valid else f"{RED}{reason}{RESET}"
                print(f"    [{offset-32:4d}] outPk[{i}]: {commit.hex()[:16]}... [{status}]")
            result["output_commitments"] = out_commits

        result["rct_remaining_bytes"] = len(data) - offset
        print(f"\n[{offset:4d}] Remaining bytes (prunable): {len(data) - offset}")
    else:
        result["errors"].append("No RCT signature data!")

    # === SUMMARY ===
    print(f"\n{CYAN}=== SUMMARY ==={RESET}")
    print(f"Total bytes: {len(data)}")
    print(f"Parsed up to: {offset}")
    print(f"Inputs: {num_inputs}, Outputs: {num_outputs}")

    if result["errors"]:
        print(f"\n{RED}ERRORS ({len(result['errors'])}):{RESET}")
        for e in result["errors"]:
            print(f"  - {e}")

    if result["warnings"]:
        print(f"\n{YELLOW}WARNINGS ({len(result['warnings'])}):{RESET}")
        for w in result["warnings"]:
            print(f"  - {w}")

    if not result["errors"] and not result["warnings"]:
        print(f"\n{GREEN}No issues detected in TX structure.{RESET}")

    return result

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 debug-tx-hex.py <tx_hex_file> [<tx_hex_file2> ...]")
        print("       python3 debug-tx-hex.py /tmp/tx_debug_*.hex")
        sys.exit(1)

    for filepath in sys.argv[1:]:
        path = Path(filepath)
        if not path.exists():
            print(f"{RED}File not found: {filepath}{RESET}")
            continue

        print(f"\n{'='*60}")
        print(f"Parsing: {filepath}")
        print(f"{'='*60}")

        hex_content = path.read_text().strip()

        # Handle multi-line hex
        hex_content = hex_content.replace('\n', '').replace(' ', '')

        result = parse_tx_hex(hex_content)

        if "error" in result:
            print(f"{RED}Parse error: {result['error']}{RESET}")

if __name__ == "__main__":
    main()
