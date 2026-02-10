/* @ts-self-types="./wallet_wasm.d.ts" */

/**
 * Complete a partial transaction (Signer 2)
 *
 * This function:
 * 1. Decrypts alpha from Signer 1
 * 2. Adds Signer 2's contribution to s[signer_index]
 * 3. Returns the completed CLSAG signature
 * @param {string} spend_key_priv_hex
 * @param {string} mask_share_hex
 * @param {string} partial_tx_json
 * @returns {any}
 */
export function complete_partial_tx_wasm(spend_key_priv_hex, mask_share_hex, partial_tx_json) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passStringToWasm0(spend_key_priv_hex, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(mask_share_hex, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(partial_tx_json, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len2 = WASM_VECTOR_LEN;
        wasm.complete_partial_tx_wasm(retptr, ptr0, len0, ptr1, len1, ptr2, len2);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        if (r2) {
            throw takeObject(r1);
        }
        return takeObject(r0);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
}

/**
 * Create a key image from spend key (SINGLE-SIGNER MODE)
 *
 * Key image I = x * H(P) where:
 * - x is the private spend key
 * - P = x*G is the public spend key
 * - H is the hash-to-point function
 *
 * **WARNING**: This is for single-signer wallets only!
 * For 2-of-3 multisig, use `compute_partial_key_image()` instead.
 *
 * # Parameters
 * - `spend_key_priv_hex`: Private spend key (hex, 64 chars)
 *
 * # Returns
 * ```json
 * {
 *   "keyImage": "hex-encoded 32-byte key image",
 *   "publicKey": "hex-encoded 32-byte public key"
 * }
 * ```
 * @param {string} spend_key_priv_hex
 * @returns {any}
 */
export function compute_key_image(spend_key_priv_hex) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passStringToWasm0(spend_key_priv_hex, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len0 = WASM_VECTOR_LEN;
        wasm.compute_key_image(retptr, ptr0, len0);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        if (r2) {
            throw takeObject(r1);
        }
        return takeObject(r0);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
}

/**
 * Compute partial key image for multisig signing
 *
 * For 2-of-3 multisig, each signer contributes a partial key image:
 * - pKI_i = x_i * Hp(P_multisig)
 *
 * The server aggregates partial key images from 2 signers:
 * - KI_combined = pKI_1 + pKI_2
 *
 * This ensures all signers produce the SAME key image for the same input,
 * which is required for valid Monero ring signatures.
 *
 * # Parameters
 * - `spend_key_priv_hex`: Signer's private spend key (hex, 64 chars)
 * - `multisig_pub_key_hex`: Multisig address's public spend key (hex, 64 chars)
 *   This is the combined public key: P_multisig = P_buyer + P_vendor + P_arbiter
 *
 * # Returns
 * ```json
 * {
 *   "partialKeyImage": "hex-encoded 32-byte partial key image contribution",
 *   "multisigPubKey": "hex-encoded 32-byte multisig public key (echo for verification)"
 * }
 * ```
 *
 * # Security
 * - The partial key image does NOT reveal the private spend key
 * - Safe to send to server for aggregation
 * - Both signers' partials are needed to reconstruct the full key image
 *
 * # CRITICAL (v0.8.4)
 * The second parameter MUST be the ONE-TIME OUTPUT PUBLIC KEY (P)
 * NOT the multisig address spend pubkey (B).
 *
 * P = ring[signer_idx][0] = the actual output being spent
 * B = multisig address component (WRONG for key image!)
 *
 * Formula: pKI = x * Hp(P) where P is the one-time output key
 * @param {string} spend_key_priv_hex
 * @param {string} one_time_pubkey_hex
 * @param {string} lagrange_coefficient_hex
 * @returns {any}
 */
export function compute_partial_key_image(spend_key_priv_hex, one_time_pubkey_hex, lagrange_coefficient_hex) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passStringToWasm0(spend_key_priv_hex, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(one_time_pubkey_hex, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(lagrange_coefficient_hex, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len2 = WASM_VECTOR_LEN;
        wasm.compute_partial_key_image(retptr, ptr0, len0, ptr1, len1, ptr2, len2);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        if (r2) {
            throw takeObject(r1);
        }
        return takeObject(r0);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
}

/**
 * Compute partial key image WITH output secret derivation
 *
 * This is the CORRECT implementation for spending Monero one-time outputs.
 *
 * In Monero, when funds are sent to an address (A, B) with view key a and spend key b:
 * - Sender creates: P = H_s(r·A || idx)·G + B  (one-time output pubkey)
 * - Receiver spends with: x = H_s(a·R || idx) + b  (output secret key)
 *
 * For 2-of-3 multisig:
 * - B = b1·G + b2·G + b3·G (sum of public keys)
 * - To spend: x = H_s(a_shared·R || idx) + (b1 + b2) for 2 signers
 * - Each signer computes: pKI_i = (H_s(a·R || idx) + b_i) * Hp(P)
 *
 * # Parameters
 * - `spend_key_hex`: Signer's private spend key share (hex, 64 chars)
 * - `tx_pub_key_hex`: TX public key R from the FUNDING transaction (hex, 64 chars)
 * - `view_key_shared_hex`: Shared multisig view key (hex, 64 chars)
 * - `output_index`: Output index in the funding transaction (typically 0)
 * - `one_time_pubkey_hex`: The one-time output public key P (hex, 64 chars)
 *
 * # Returns
 * ```json
 * {
 *   "partialKeyImage": "hex-encoded 32-byte partial key image",
 *   "derivationScalar": "hex-encoded derivation H_s(a·R || idx) for debugging"
 * }
 * ```
 *
 * # Cryptographic Details
 * ```
 * shared_secret = a_shared * R  (point multiplication)
 * derivation = H_s(shared_secret || output_index)  (hash-to-scalar)
 * effective_spend = derivation + spend_share
 * pKI = effective_spend * Hp(P)
 * ```
 * @param {string} spend_key_hex
 * @param {string} tx_pub_key_hex
 * @param {string} view_key_shared_hex
 * @param {bigint} output_index
 * @param {string} one_time_pubkey_hex
 * @param {string} lagrange_coefficient_hex
 * @returns {any}
 */
export function compute_partial_key_image_with_derivation(spend_key_hex, tx_pub_key_hex, view_key_shared_hex, output_index, one_time_pubkey_hex, lagrange_coefficient_hex) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passStringToWasm0(spend_key_hex, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(tx_pub_key_hex, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(view_key_shared_hex, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passStringToWasm0(one_time_pubkey_hex, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len3 = WASM_VECTOR_LEN;
        const ptr4 = passStringToWasm0(lagrange_coefficient_hex, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len4 = WASM_VECTOR_LEN;
        wasm.compute_partial_key_image_with_derivation(retptr, ptr0, len0, ptr1, len1, ptr2, len2, output_index, ptr3, len3, ptr4, len4);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        if (r2) {
            throw takeObject(r1);
        }
        return takeObject(r0);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
}

/**
 * Create encrypted partial signature for relay (convenience wrapper)
 *
 * Combines keypair generation and encryption in one call.
 *
 * # Arguments
 * * `partial_data_json` - JSON string of PartialSignatureData
 * * `peer_pubkey_hex` - Peer's ephemeral public key (hex)
 *
 * # Returns
 * JSON with encrypted_blob (base64), nonce_hex, ephemeral_pubkey_hex, private_key_hex
 * @param {string} partial_data_json
 * @param {string} peer_pubkey_hex
 * @returns {any}
 */
export function create_encrypted_partial_for_relay(partial_data_json, peer_pubkey_hex) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passStringToWasm0(partial_data_json, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(peer_pubkey_hex, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len1 = WASM_VECTOR_LEN;
        wasm.create_encrypted_partial_for_relay(retptr, ptr0, len0, ptr1, len1);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        if (r2) {
            throw takeObject(r1);
        }
        return takeObject(r0);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
}

/**
 * Create a partial transaction (Signer 1) - v0.8.4 with derivation support
 *
 * This function:
 * 1. Computes output secret: x = H_s(a·R||idx) + b (if derivation provided)
 * 2. Generates a random nonce alpha
 * 3. Computes the CLSAG ring loop
 * 4. Creates partial s[signer_index] with Signer 1's contribution
 * 5. Encrypts alpha for Signer 2
 *
 * v0.8.4: Added optional derivation parameters for asymmetric PKI
 * - Vendor (Signer 1) MUST include derivation
 * - tx_pub_key_hex, view_key_hex, output_index are optional but recommended
 * @param {string} spend_key_priv_hex
 * @param {string} mask_share_hex
 * @param {string} signer2_public_hex
 * @param {string} input_data_json
 * @param {string} tx_prefix_hash_hex
 * @param {string} key_image_hex
 * @param {string} multisig_pub_key_hex
 * @returns {any}
 */
export function create_partial_tx_wasm(spend_key_priv_hex, mask_share_hex, signer2_public_hex, input_data_json, tx_prefix_hash_hex, key_image_hex, multisig_pub_key_hex) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passStringToWasm0(spend_key_priv_hex, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(mask_share_hex, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(signer2_public_hex, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passStringToWasm0(input_data_json, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len3 = WASM_VECTOR_LEN;
        const ptr4 = passStringToWasm0(tx_prefix_hash_hex, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len4 = WASM_VECTOR_LEN;
        const ptr5 = passStringToWasm0(key_image_hex, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len5 = WASM_VECTOR_LEN;
        const ptr6 = passStringToWasm0(multisig_pub_key_hex, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len6 = WASM_VECTOR_LEN;
        wasm.create_partial_tx_wasm(retptr, ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4, ptr5, len5, ptr6, len6);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        if (r2) {
            throw takeObject(r1);
        }
        return takeObject(r0);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
}

/**
 * Create a partial transaction (Signer 1) with derivation support
 *
 * v0.8.4: Full version with derivation parameters
 * - tx_pub_key_hex: The R from the funding transaction
 * - view_key_hex: The shared view private key (a)
 * - output_index: Index of the output in the transaction
 *
 * If derivation parameters are provided, computes:
 *   x = H_s(a·R || output_index) + b
 * Otherwise, uses x = b (raw spend key)
 * @param {string} spend_key_priv_hex
 * @param {string} mask_share_hex
 * @param {string} signer2_public_hex
 * @param {string} input_data_json
 * @param {string} tx_prefix_hash_hex
 * @param {string} key_image_hex
 * @param {string} multisig_pub_key_hex
 * @param {string} tx_pub_key_hex
 * @param {string} view_key_hex
 * @param {bigint} output_index
 * @returns {any}
 */
export function create_partial_tx_wasm_with_derivation(spend_key_priv_hex, mask_share_hex, signer2_public_hex, input_data_json, tx_prefix_hash_hex, key_image_hex, multisig_pub_key_hex, tx_pub_key_hex, view_key_hex, output_index) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passStringToWasm0(spend_key_priv_hex, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(mask_share_hex, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(signer2_public_hex, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passStringToWasm0(input_data_json, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len3 = WASM_VECTOR_LEN;
        const ptr4 = passStringToWasm0(tx_prefix_hash_hex, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len4 = WASM_VECTOR_LEN;
        const ptr5 = passStringToWasm0(key_image_hex, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len5 = WASM_VECTOR_LEN;
        const ptr6 = passStringToWasm0(multisig_pub_key_hex, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len6 = WASM_VECTOR_LEN;
        const ptr7 = passStringToWasm0(tx_pub_key_hex, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len7 = WASM_VECTOR_LEN;
        const ptr8 = passStringToWasm0(view_key_hex, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len8 = WASM_VECTOR_LEN;
        wasm.create_partial_tx_wasm_with_derivation(retptr, ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4, ptr5, len5, ptr6, len6, ptr7, len7, ptr8, len8, output_index);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        if (r2) {
            throw takeObject(r1);
        }
        return takeObject(r0);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
}

/**
 * Decrypt partial signature from relay
 *
 * # Arguments
 * * `encrypted_blob_base64` - Base64-encoded ciphertext
 * * `nonce_hex` - Hex-encoded nonce (12 bytes)
 * * `peer_pubkey_hex` - First signer's ephemeral public key (hex)
 * * `my_private_key_hex` - My ephemeral private key (hex)
 *
 * # Returns
 * JSON with partial_data_json (decrypted)
 * @param {string} encrypted_blob_base64
 * @param {string} nonce_hex
 * @param {string} peer_pubkey_hex
 * @param {string} my_private_key_hex
 * @returns {any}
 */
export function decrypt_partial_signature(encrypted_blob_base64, nonce_hex, peer_pubkey_hex, my_private_key_hex) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passStringToWasm0(encrypted_blob_base64, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(nonce_hex, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(peer_pubkey_hex, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passStringToWasm0(my_private_key_hex, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len3 = WASM_VECTOR_LEN;
        wasm.decrypt_partial_signature(retptr, ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        if (r2) {
            throw takeObject(r1);
        }
        return takeObject(r0);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
}

/**
 * Debug function to dump all CLSAG parameters for comparison with reference implementations
 * @param {string} signature_json
 * @param {string} ring_json
 * @param {string} tx_prefix_hash_hex
 * @returns {any}
 */
export function dump_clsag_params_wasm(signature_json, ring_json, tx_prefix_hash_hex) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passStringToWasm0(signature_json, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(ring_json, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(tx_prefix_hash_hex, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len2 = WASM_VECTOR_LEN;
        wasm.dump_clsag_params_wasm(retptr, ptr0, len0, ptr1, len1, ptr2, len2);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        if (r2) {
            throw takeObject(r1);
        }
        return takeObject(r0);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
}

/**
 * Encrypt partial signature data for relay
 *
 * # Arguments
 * * `partial_data_json` - JSON string of PartialSignatureData
 * * `my_private_key_hex` - My ephemeral private key (hex)
 * * `peer_pubkey_hex` - Peer's ephemeral public key (hex)
 *
 * # Returns
 * JSON with encrypted_blob (base64), nonce_hex, ephemeral_pubkey_hex
 * @param {string} partial_data_json
 * @param {string} my_private_key_hex
 * @param {string} peer_pubkey_hex
 * @returns {any}
 */
export function encrypt_partial_signature(partial_data_json, my_private_key_hex, peer_pubkey_hex) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passStringToWasm0(partial_data_json, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(my_private_key_hex, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(peer_pubkey_hex, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len2 = WASM_VECTOR_LEN;
        wasm.encrypt_partial_signature(retptr, ptr0, len0, ptr1, len1, ptr2, len2);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        if (r2) {
            throw takeObject(r1);
        }
        return takeObject(r0);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
}

/**
 * Compute Lagrange coefficient for a signer in a signing session
 *
 * For 2-of-3 threshold signing, the Lagrange coefficient determines how to
 * reconstruct the group secret from the participating shares.
 *
 * # Arguments
 * * `signer_index` - The index of the signer (1, 2, or 3)
 * * `all_signer_indices` - Array of all participating signer indices (e.g., [1, 2])
 *
 * # Returns
 * The Lagrange coefficient as a 32-byte hex scalar
 * @param {number} signer_index
 * @param {number} signer1_index
 * @param {number} signer2_index
 * @returns {string}
 */
export function frost_compute_lagrange_coefficient(signer_index, signer1_index, signer2_index) {
    let deferred2_0;
    let deferred2_1;
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        wasm.frost_compute_lagrange_coefficient(retptr, signer_index, signer1_index, signer2_index);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
        var ptr1 = r0;
        var len1 = r1;
        if (r3) {
            ptr1 = 0; len1 = 0;
            throw takeObject(r2);
        }
        deferred2_0 = ptr1;
        deferred2_1 = len1;
        return getStringFromWasm0(ptr1, len1);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
        wasm.__wbindgen_export4(deferred2_0, deferred2_1, 1);
    }
}

/**
 * Derive Monero address and shared view key for a FROST escrow
 *
 * The spend public key is the group_pubkey from DKG.
 * The view key is deterministically derived from the escrow_id and group_pubkey,
 * ensuring all participants compute the same keys.
 *
 * # Arguments
 * * `group_pubkey_hex` - The group public key from DKG (64 hex chars = 32 bytes)
 * * `escrow_id` - The escrow identifier (used as domain separator)
 * * `network` - Optional network: "mainnet", "stagenet", "testnet". Defaults to "mainnet".
 *
 * # Returns
 * * `address` - The Monero address for this FROST escrow
 * * `view_key_private` - The shared view key (hex) - used for blockchain monitoring
 * * `view_key_public` - The view public key (hex)
 * * `network` - The network used
 * @param {string} group_pubkey_hex
 * @param {string} escrow_id
 * @param {string | null} [network]
 * @returns {any}
 */
export function frost_derive_address(group_pubkey_hex, escrow_id, network) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passStringToWasm0(group_pubkey_hex, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(escrow_id, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len1 = WASM_VECTOR_LEN;
        var ptr2 = isLikeNone(network) ? 0 : passStringToWasm0(network, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        var len2 = WASM_VECTOR_LEN;
        wasm.frost_derive_address(retptr, ptr0, len0, ptr1, len1, ptr2, len2);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        if (r2) {
            throw takeObject(r1);
        }
        return takeObject(r0);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
}

/**
 * DKG Round 1: Generate commitment and secret polynomial
 *
 * Each participant calls this independently. Returns:
 * - `round1_package`: Public data to share with all other participants
 * - `secret_package`: Private data to keep locally for Round 2
 *
 * # Arguments
 * * `participant_index` - 1, 2, or 3 (buyer=1, vendor=2, arbiter=3)
 * * `threshold` - Minimum signers required (always 2 for 2-of-3)
 * * `max_signers` - Total number of signers (always 3)
 * @param {number} participant_index
 * @param {number} threshold
 * @param {number} max_signers
 * @returns {any}
 */
export function frost_dkg_part1(participant_index, threshold, max_signers) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        wasm.frost_dkg_part1(retptr, participant_index, threshold, max_signers);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        if (r2) {
            throw takeObject(r1);
        }
        return takeObject(r0);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
}

/**
 * DKG Round 2: Compute secret shares from OTHER participants' Round 1 packages
 *
 * Called after all participants have submitted their Round 1 packages.
 *
 * # Arguments
 * * `secret_package_hex` - The secret_package from frost_dkg_part1 (hex)
 * * `other_round1_packages_json` - JSON with ONLY OTHER participants: { "2": "hex...", "3": "hex..." }
 *                                   (exclude your own package - it's in secret_package)
 * @param {string} secret_package_hex
 * @param {string} all_round1_packages_json
 * @returns {any}
 */
export function frost_dkg_part2(secret_package_hex, all_round1_packages_json) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passStringToWasm0(secret_package_hex, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(all_round1_packages_json, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len1 = WASM_VECTOR_LEN;
        wasm.frost_dkg_part2(retptr, ptr0, len0, ptr1, len1);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        if (r2) {
            throw takeObject(r1);
        }
        return takeObject(r0);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
}

/**
 * DKG Round 3: Finalize and get KeyPackage
 *
 * Called after receiving Round 2 packages from other participants.
 *
 * # Arguments
 * * `round2_secret_hex` - The round2_secret from frost_dkg_part2 (hex)
 * * `round1_packages_json` - All Round 1 packages: { "1": "hex...", "2": "hex...", "3": "hex..." }
 * * `round2_packages_json` - Round 2 packages received from others: { "1": "hex...", "2": "hex..." }
 * @param {string} round2_secret_hex
 * @param {string} round1_packages_json
 * @param {string} round2_packages_json
 * @returns {any}
 */
export function frost_dkg_part3(round2_secret_hex, round1_packages_json, round2_packages_json) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passStringToWasm0(round2_secret_hex, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(round1_packages_json, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(round2_packages_json, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len2 = WASM_VECTOR_LEN;
        wasm.frost_dkg_part3(retptr, ptr0, len0, ptr1, len1, ptr2, len2);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        if (r2) {
            throw takeObject(r1);
        }
        return takeObject(r0);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
}

/**
 * Extract the secret share scalar from a KeyPackage
 *
 * Returns the raw 32-byte secret share as hex, suitable for use in CLSAG signing.
 * @param {string} key_package_hex
 * @returns {string}
 */
export function frost_extract_secret_share(key_package_hex) {
    let deferred3_0;
    let deferred3_1;
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passStringToWasm0(key_package_hex, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len0 = WASM_VECTOR_LEN;
        wasm.frost_extract_secret_share(retptr, ptr0, len0);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
        var ptr2 = r0;
        var len2 = r1;
        if (r3) {
            ptr2 = 0; len2 = 0;
            throw takeObject(r2);
        }
        deferred3_0 = ptr2;
        deferred3_1 = len2;
        return getStringFromWasm0(ptr2, len2);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
        wasm.__wbindgen_export4(deferred3_0, deferred3_1, 1);
    }
}

/**
 * Get the participant index from a role string
 * @param {string} role
 * @returns {number}
 */
export function frost_role_to_index(role) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passStringToWasm0(role, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len0 = WASM_VECTOR_LEN;
        wasm.frost_role_to_index(retptr, ptr0, len0);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        if (r2) {
            throw takeObject(r1);
        }
        return r0;
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
}

/**
 * Generate an ephemeral X25519 keypair for ECDH
 *
 * Returns JSON with private_key_hex and public_key_hex
 * @returns {any}
 */
export function generate_ephemeral_keypair() {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        wasm.generate_ephemeral_keypair(retptr);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        if (r2) {
            throw takeObject(r1);
        }
        return takeObject(r0);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
}

/**
 * Generate a new Monero wallet with spend/view keys
 *
 * Returns:
 * ```json
 * {
 *   "seed": "12-word BIP39 mnemonic",
 *   "address": "4...",
 *   "viewKeyPub": "hex",
 *   "spendKeyPub": "hex",
 *   "viewKeyPriv": "hex",  // WARNING: Handle with care!
 *   "spendKeyPriv": "hex"  // WARNING: Handle with care!
 * }
 * ```
 *
 * **SECURITY:**
 * - Private keys returned ONCE for user backup
 * - Caller must store securely (encrypted IndexedDB)
 *
 * # Parameters
 * - `network`: Optional - "mainnet", "stagenet", "testnet". Defaults to "mainnet".
 * @param {string | null} [network]
 * @returns {any}
 */
export function generate_monero_wallet(network) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        var ptr0 = isLikeNone(network) ? 0 : passStringToWasm0(network, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        var len0 = WASM_VECTOR_LEN;
        wasm.generate_monero_wallet(retptr, ptr0, len0);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        if (r2) {
            throw takeObject(r1);
        }
        return takeObject(r0);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
}

/**
 * Generate MuSig2-style nonce commitment for CLSAG multisig
 *
 * **v0.9.0 FIX:** To solve the "Sanity check failed" issue where each signer
 * had unique alpha causing L₁ ≠ L₂, we implement MuSig2-style nonce aggregation:
 * 1. Each signer generates random α (nonce)
 * 2. Computes R = α*G and R' = α*Hp(P)
 * 3. Computes commitment H(R || R')
 * 4. Returns {commitment_hash, r_public, r_prime_public, alpha_secret}
 * 5. alpha_secret stored in JS memory (NOT localStorage)
 * 6. Server aggregates: R_agg = R₁ + R₂
 * 7. Both signers use R_agg for L in their signatures
 *
 * **Security:** alpha_secret returned to JS, kept in window.tempNonceAlpha
 * @param {string} _tx_prefix_hash
 * @param {string} multisig_pub_key
 * @returns {any}
 */
export function generate_nonce_commitment(_tx_prefix_hash, multisig_pub_key) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passStringToWasm0(_tx_prefix_hash, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(multisig_pub_key, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len1 = WASM_VECTOR_LEN;
        wasm.generate_nonce_commitment(retptr, ptr0, len0, ptr1, len1);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        if (r2) {
            throw takeObject(r1);
        }
        return takeObject(r0);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
}

/**
 * Generate a new Monero wallet from a random BIP39 seed
 *
 * # Arguments
 * * `network` - Optional network: "mainnet", "stagenet", "testnet". Defaults to "mainnet".
 * @param {string | null} [network]
 * @returns {any}
 */
export function generate_wallet(network) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        var ptr0 = isLikeNone(network) ? 0 : passStringToWasm0(network, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        var len0 = WASM_VECTOR_LEN;
        wasm.generate_wallet(retptr, ptr0, len0);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        if (r2) {
            throw takeObject(r1);
        }
        return takeObject(r0);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
}

/**
 * Get multisig session status
 *
 * # Parameters
 * - `escrow_id`: Escrow session identifier
 *
 * # Returns
 * - StatusResponse with current stage and multisig address (if Ready)
 * @param {string} escrow_id
 * @returns {Promise<any>}
 */
export function get_multisig_status(escrow_id) {
    const ptr0 = passStringToWasm0(escrow_id, wasm.__wbindgen_export, wasm.__wbindgen_export2);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.get_multisig_status(ptr0, len0);
    return takeObject(ret);
}

/**
 * Get peer multisig info
 *
 * Called by a participant to retrieve multisig blobs from other parties.
 * Used after submitting own info to proceed to next round.
 *
 * # Parameters
 * - `escrow_id`: Escrow session identifier
 * - `user_id`: Current user's identifier
 *
 * # Returns
 * - PeerInfoResponse with array of peer multisig blobs
 *
 * # Security
 * - Server acts as relay only
 * - Each peer's blob is opaque (no key extraction possible)
 * @param {string} escrow_id
 * @param {string} user_id
 * @returns {Promise<any>}
 */
export function get_peer_multisig_info(escrow_id, user_id) {
    const ptr0 = passStringToWasm0(escrow_id, wasm.__wbindgen_export, wasm.__wbindgen_export2);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(user_id, wasm.__wbindgen_export, wasm.__wbindgen_export2);
    const len1 = WASM_VECTOR_LEN;
    const ret = wasm.get_peer_multisig_info(ptr0, len0, ptr1, len1);
    return takeObject(ret);
}

/**
 * Initialize a new multisig coordination session
 *
 * Called by the escrow initiator (typically the buyer or platform).
 *
 * # Parameters
 * - `escrow_id`: Unique escrow identifier (UUID)
 * - `participants_json`: JSON array of ParticipantDto
 *
 * # Returns
 * - Success: `{success: true, message: "...", escrow_id: "..."}`
 * - Error: Throws JS exception with error details
 *
 * # Security
 * - This only creates coordination metadata
 * - No wallet keys are transmitted
 * @param {string} escrow_id
 * @param {string} participants_json
 * @returns {Promise<any>}
 */
export function init_multisig_session(escrow_id, participants_json) {
    const ptr0 = passStringToWasm0(escrow_id, wasm.__wbindgen_export, wasm.__wbindgen_export2);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(participants_json, wasm.__wbindgen_export, wasm.__wbindgen_export2);
    const len1 = WASM_VECTOR_LEN;
    const ret = wasm.init_multisig_session(ptr0, len0, ptr1, len1);
    return takeObject(ret);
}

/**
 * Make multisig (Round 2) - Finalize multisig address
 *
 * Takes peer multisig info blobs and combines them to create the final
 * 2-of-3 multisig address.
 *
 * # Parameters
 * - `spend_key_priv_hex`: Your private spend key (hex, 64 chars)
 * - `my_view_key_hex`: Your private view key component (hex, 64 chars)
 * - `peer_view_keys_json`: JSON array of peer view key components (hex strings)
 * - `peer_infos_json`: JSON array of peer multisig_info blobs (base64)
 *
 * # Returns
 * ```json
 * {
 *   "multisigAddress": "9...",
 *   "sharedViewKey": "hex",  // Private view key for server monitoring
 *   "stage": "ready",
 *   "threshold": 2,
 *   "total": 3
 * }
 * ```
 *
 * **SECURITY:**
 * - `sharedViewKey` is derived using Monero's official protocol:
 *   b_shared = b_buyer + b_vendor + b_arbiter (mod l)
 * - It allows VIEWING balance/transactions but NOT spending
 * - Safe to send to server for balance monitoring
 * - All 3 participants generate the SAME shared view key (deterministic)
 *
 * **LIMITATIONS:**
 * - This is a SIMPLIFIED implementation for PoC
 * - Production version must use monero-wallet-rpc via server proxy
 * @param {string} spend_key_priv_hex
 * @param {string} my_view_key_hex
 * @param {string} peer_view_keys_json
 * @param {string} peer_infos_json
 * @returns {any}
 */
export function make_multisig_wasm(spend_key_priv_hex, my_view_key_hex, peer_view_keys_json, peer_infos_json) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passStringToWasm0(spend_key_priv_hex, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(my_view_key_hex, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(peer_view_keys_json, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passStringToWasm0(peer_infos_json, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len3 = WASM_VECTOR_LEN;
        wasm.make_multisig_wasm(retptr, ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        if (r2) {
            throw takeObject(r1);
        }
        return takeObject(r0);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
}

/**
 * Prepare multisig (Round 1) - Generate multisig info blob
 *
 * This generates the cryptographic material needed for 2-of-3 multisig setup.
 * The blob is opaque and safe to send to the server for relay to peers.
 *
 * # Parameters
 * - `spend_key_priv_hex`: Private spend key (hex, 64 chars)
 * - `view_key_priv_hex`: Private view key (hex, 64 chars)
 *
 * # Returns
 * ```json
 * {
 *   "multisigInfo": "base64-encoded blob",
 *   "stage": "prepared"
 * }
 * ```
 *
 * **SECURITY:**
 * - The multisig_info blob does NOT contain raw private keys
 * - It contains public key commitments + proofs
 * - Safe to relay through untrusted server
 * @param {string} spend_key_priv_hex
 * @param {string} view_key_priv_hex
 * @returns {any}
 */
export function prepare_multisig_wasm(spend_key_priv_hex, view_key_priv_hex) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passStringToWasm0(spend_key_priv_hex, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(view_key_priv_hex, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len1 = WASM_VECTOR_LEN;
        wasm.prepare_multisig_wasm(retptr, ptr0, len0, ptr1, len1);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        if (r2) {
            throw takeObject(r1);
        }
        return takeObject(r0);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
}

/**
 * Restore wallet from seed phrase
 *
 * # Parameters
 * - `seed_phrase`: 12-word BIP39 mnemonic
 * - `network`: Optional - "mainnet", "stagenet", "testnet". Defaults to "mainnet".
 *
 * # Returns
 * Same structure as `generate_monero_wallet()`
 * @param {string} seed_phrase
 * @param {string | null} [network]
 * @returns {any}
 */
export function restore_wallet_from_seed(seed_phrase, network) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passStringToWasm0(seed_phrase, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len0 = WASM_VECTOR_LEN;
        var ptr1 = isLikeNone(network) ? 0 : passStringToWasm0(network, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        var len1 = WASM_VECTOR_LEN;
        wasm.restore_wallet_from_seed(retptr, ptr0, len0, ptr1, len1);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        if (r2) {
            throw takeObject(r1);
        }
        return takeObject(r0);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
}

/**
 * Sign with partial key for 2-of-3 multisig CLSAG
 *
 * Unlike `sign_clsag_wasm()` which requires the full private key matching the public
 * key in the ring, this function is designed for multisig where each participant
 * holds only a partial key (x_i) and the ring contains the AGGREGATED public key
 * (P_multisig = P_1 + P_2 + P_3).
 *
 * # Multisig Key Relationship
 * - Each signer has: x_i (partial private key) and P_i = x_i * G (partial public key)
 * - The ring contains: P_multisig = P_1 + P_2 + P_3
 * - Key image: KI = (x_1 + x_2) * Hp(P_multisig) for 2-of-3
 *
 * # Parameters
 * - `spend_key_priv_hex`: Signer's PARTIAL private spend key (hex, 64 chars)
 * - `input_data_json`: Ring data from server (same as sign_clsag_wasm)
 * - `tx_prefix_hash_hex`: Transaction prefix hash (32 bytes hex)
 * - `multisig_pub_key_hex`: The AGGREGATED multisig public key P_multisig
 *
 * # Returns
 * Partial signature components that can be aggregated server-side:
 * ```json
 * {
 *   "signature": { "D": "...", "s": [...], "c1": "..." },
 *   "keyImage": "...",          // Partial key image (NOT final)
 *   "partialKeyImage": "...",   // Same as keyImage for clarity
 *   "pseudoOut": "..."
 * }
 * ```
 * @param {string} spend_key_priv_hex
 * @param {string} input_data_json
 * @param {string} tx_prefix_hash_hex
 * @param {string} multisig_pub_key_hex
 * @param {string} aggregated_key_image_hex
 * @param {string | null | undefined} first_signer_c1_hex
 * @param {string | null | undefined} first_signer_s_values_json
 * @param {string | null | undefined} first_signer_d_hex
 * @param {string | null | undefined} mu_p_hex
 * @param {string | null | undefined} mu_c_hex
 * @param {string | null | undefined} first_signer_pseudo_out_hex
 * @param {boolean} first_signer_used_r_agg
 * @param {string} lagrange_coefficient_hex
 * @returns {any}
 */
export function sign_clsag_partial_wasm(spend_key_priv_hex, input_data_json, tx_prefix_hash_hex, multisig_pub_key_hex, aggregated_key_image_hex, first_signer_c1_hex, first_signer_s_values_json, first_signer_d_hex, mu_p_hex, mu_c_hex, first_signer_pseudo_out_hex, first_signer_used_r_agg, lagrange_coefficient_hex) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passStringToWasm0(spend_key_priv_hex, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(input_data_json, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(tx_prefix_hash_hex, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passStringToWasm0(multisig_pub_key_hex, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len3 = WASM_VECTOR_LEN;
        const ptr4 = passStringToWasm0(aggregated_key_image_hex, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len4 = WASM_VECTOR_LEN;
        var ptr5 = isLikeNone(first_signer_c1_hex) ? 0 : passStringToWasm0(first_signer_c1_hex, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        var len5 = WASM_VECTOR_LEN;
        var ptr6 = isLikeNone(first_signer_s_values_json) ? 0 : passStringToWasm0(first_signer_s_values_json, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        var len6 = WASM_VECTOR_LEN;
        var ptr7 = isLikeNone(first_signer_d_hex) ? 0 : passStringToWasm0(first_signer_d_hex, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        var len7 = WASM_VECTOR_LEN;
        var ptr8 = isLikeNone(mu_p_hex) ? 0 : passStringToWasm0(mu_p_hex, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        var len8 = WASM_VECTOR_LEN;
        var ptr9 = isLikeNone(mu_c_hex) ? 0 : passStringToWasm0(mu_c_hex, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        var len9 = WASM_VECTOR_LEN;
        var ptr10 = isLikeNone(first_signer_pseudo_out_hex) ? 0 : passStringToWasm0(first_signer_pseudo_out_hex, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        var len10 = WASM_VECTOR_LEN;
        const ptr11 = passStringToWasm0(lagrange_coefficient_hex, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len11 = WASM_VECTOR_LEN;
        wasm.sign_clsag_partial_wasm(retptr, ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4, ptr5, len5, ptr6, len6, ptr7, len7, ptr8, len8, ptr9, len9, ptr10, len10, first_signer_used_r_agg, ptr11, len11);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        if (r2) {
            throw takeObject(r1);
        }
        return takeObject(r0);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
}

/**
 * Sign a single input with CLSAG ring signature
 *
 * This function creates a CLSAG signature for one input of a transaction.
 * The server must provide the ring members (decoys) and other transaction data.
 *
 * # Parameters
 * - `spend_key_priv_hex`: Your private spend key (hex, 64 chars)
 * - `input_data_json`: JSON containing ring data from server (SignInputData structure)
 * - `tx_prefix_hash_hex`: Hash of transaction prefix (what we're signing, 32 bytes hex)
 * - `pseudo_out_mask_hex`: Mask for this input's pseudo-output commitment
 *
 * # Returns
 * ```json
 * {
 *   "signature": {
 *     "D": "hex-encoded D point",
 *     "s": ["hex-encoded scalar", ...],
 *     "c1": "hex-encoded scalar"
 *   },
 *   "keyImage": "hex-encoded key image",
 *   "pseudoOut": "hex-encoded pseudo-output commitment"
 * }
 * ```
 *
 * # Architecture Notes
 * For 2-of-3 multisig:
 * 1. Each party generates a partial signature share
 * 2. Server collects 2 shares and combines them
 * 3. Combined signature is broadcast
 *
 * This function handles single-signer mode. For multisig, use sign_clsag_partial_wasm.
 * @param {string} spend_key_priv_hex
 * @param {string} input_data_json
 * @param {string} tx_prefix_hash_hex
 * @returns {any}
 */
export function sign_clsag_wasm(spend_key_priv_hex, input_data_json, tx_prefix_hash_hex) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passStringToWasm0(spend_key_priv_hex, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(input_data_json, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(tx_prefix_hash_hex, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len2 = WASM_VECTOR_LEN;
        wasm.sign_clsag_wasm(retptr, ptr0, len0, ptr1, len1, ptr2, len2);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        if (r2) {
            throw takeObject(r1);
        }
        return takeObject(r0);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
}

/**
 * LEGACY PLACEHOLDER - Use sign_clsag_wasm instead
 *
 * This function is kept for backwards compatibility but now returns
 * an error directing users to the new implementation.
 * @param {string} _unsigned_tx_hex
 * @param {string} _spend_key_priv_hex
 * @returns {any}
 */
export function sign_multisig_tx_wasm(_unsigned_tx_hex, _spend_key_priv_hex) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passStringToWasm0(_unsigned_tx_hex, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(_spend_key_priv_hex, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len1 = WASM_VECTOR_LEN;
        wasm.sign_multisig_tx_wasm(retptr, ptr0, len0, ptr1, len1);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        if (r2) {
            throw takeObject(r1);
        }
        return takeObject(r0);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
}

/**
 * Submit multisig info (Round 1 or Round 2)
 *
 * Called by each participant after running `prepare_multisig()` or
 * `make_multisig()` locally in their wallet.
 *
 * # Parameters
 * - `escrow_id`: Escrow session identifier
 * - `user_id`: Current user's identifier
 * - `multisig_info`: Base64-encoded multisig blob from wallet RPC
 * - `stage`: "initialization" or "key_exchange"
 *
 * # Returns
 * - SubmitInfoResponse with current stage
 *
 * # Security
 * - `multisig_info` is opaque to server (encrypted blob)
 * - Server cannot extract private keys from this data
 * @param {string} escrow_id
 * @param {string} user_id
 * @param {string} multisig_info
 * @param {string} stage
 * @returns {Promise<any>}
 */
export function submit_multisig_info(escrow_id, user_id, multisig_info, stage) {
    const ptr0 = passStringToWasm0(escrow_id, wasm.__wbindgen_export, wasm.__wbindgen_export2);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(user_id, wasm.__wbindgen_export, wasm.__wbindgen_export2);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(multisig_info, wasm.__wbindgen_export, wasm.__wbindgen_export2);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passStringToWasm0(stage, wasm.__wbindgen_export, wasm.__wbindgen_export2);
    const len3 = WASM_VECTOR_LEN;
    const ret = wasm.submit_multisig_info(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3);
    return takeObject(ret);
}

/**
 * Verify a CLSAG signature locally before broadcast
 * This is the exact verification the Monero daemon performs
 * @param {string} signature_json
 * @param {string} ring_json
 * @param {string} tx_prefix_hash_hex
 * @returns {any}
 */
export function verify_clsag_wasm(signature_json, ring_json, tx_prefix_hash_hex) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passStringToWasm0(signature_json, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(ring_json, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(tx_prefix_hash_hex, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len2 = WASM_VECTOR_LEN;
        wasm.verify_clsag_wasm(retptr, ptr0, len0, ptr1, len1, ptr2, len2);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        if (r2) {
            throw takeObject(r1);
        }
        return takeObject(r0);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
}

function __wbg_get_imports() {
    const import0 = {
        __proto__: null,
        __wbg_Error_8c4e43fe74559d73: function(arg0, arg1) {
            const ret = Error(getStringFromWasm0(arg0, arg1));
            return addHeapObject(ret);
        },
        __wbg_String_8f0eb39a4a4c2f66: function(arg0, arg1) {
            const ret = String(getObject(arg1));
            const ptr1 = passStringToWasm0(ret, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            const len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        },
        __wbg___wbindgen_boolean_get_bbbb1c18aa2f5e25: function(arg0) {
            const v = getObject(arg0);
            const ret = typeof(v) === 'boolean' ? v : undefined;
            return isLikeNone(ret) ? 0xFFFFFF : ret ? 1 : 0;
        },
        __wbg___wbindgen_debug_string_0bc8482c6e3508ae: function(arg0, arg1) {
            const ret = debugString(getObject(arg1));
            const ptr1 = passStringToWasm0(ret, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            const len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        },
        __wbg___wbindgen_in_47fa6863be6f2f25: function(arg0, arg1) {
            const ret = getObject(arg0) in getObject(arg1);
            return ret;
        },
        __wbg___wbindgen_is_function_0095a73b8b156f76: function(arg0) {
            const ret = typeof(getObject(arg0)) === 'function';
            return ret;
        },
        __wbg___wbindgen_is_object_5ae8e5880f2c1fbd: function(arg0) {
            const val = getObject(arg0);
            const ret = typeof(val) === 'object' && val !== null;
            return ret;
        },
        __wbg___wbindgen_is_string_cd444516edc5b180: function(arg0) {
            const ret = typeof(getObject(arg0)) === 'string';
            return ret;
        },
        __wbg___wbindgen_is_undefined_9e4d92534c42d778: function(arg0) {
            const ret = getObject(arg0) === undefined;
            return ret;
        },
        __wbg___wbindgen_jsval_loose_eq_9dd77d8cd6671811: function(arg0, arg1) {
            const ret = getObject(arg0) == getObject(arg1);
            return ret;
        },
        __wbg___wbindgen_number_get_8ff4255516ccad3e: function(arg0, arg1) {
            const obj = getObject(arg1);
            const ret = typeof(obj) === 'number' ? obj : undefined;
            getDataViewMemory0().setFloat64(arg0 + 8 * 1, isLikeNone(ret) ? 0 : ret, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, !isLikeNone(ret), true);
        },
        __wbg___wbindgen_string_get_72fb696202c56729: function(arg0, arg1) {
            const obj = getObject(arg1);
            const ret = typeof(obj) === 'string' ? obj : undefined;
            var ptr1 = isLikeNone(ret) ? 0 : passStringToWasm0(ret, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            var len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        },
        __wbg___wbindgen_throw_be289d5034ed271b: function(arg0, arg1) {
            throw new Error(getStringFromWasm0(arg0, arg1));
        },
        __wbg__wbg_cb_unref_d9b87ff7982e3b21: function(arg0) {
            getObject(arg0)._wbg_cb_unref();
        },
        __wbg_call_389efe28435a9388: function() { return handleError(function (arg0, arg1) {
            const ret = getObject(arg0).call(getObject(arg1));
            return addHeapObject(ret);
        }, arguments); },
        __wbg_call_4708e0c13bdc8e95: function() { return handleError(function (arg0, arg1, arg2) {
            const ret = getObject(arg0).call(getObject(arg1), getObject(arg2));
            return addHeapObject(ret);
        }, arguments); },
        __wbg_crypto_86f2631e91b51511: function(arg0) {
            const ret = getObject(arg0).crypto;
            return addHeapObject(ret);
        },
        __wbg_error_9a7fe3f932034cde: function(arg0) {
            console.error(getObject(arg0));
        },
        __wbg_fetch_e6e8e0a221783759: function(arg0, arg1) {
            const ret = getObject(arg0).fetch(getObject(arg1));
            return addHeapObject(ret);
        },
        __wbg_getRandomValues_b3f15fcbfabb0f8b: function() { return handleError(function (arg0, arg1) {
            getObject(arg0).getRandomValues(getObject(arg1));
        }, arguments); },
        __wbg_get_with_ref_key_1dc361bd10053bfe: function(arg0, arg1) {
            const ret = getObject(arg0)[getObject(arg1)];
            return addHeapObject(ret);
        },
        __wbg_headers_5a897f7fee9a0571: function(arg0) {
            const ret = getObject(arg0).headers;
            return addHeapObject(ret);
        },
        __wbg_instanceof_ArrayBuffer_c367199e2fa2aa04: function(arg0) {
            let result;
            try {
                result = getObject(arg0) instanceof ArrayBuffer;
            } catch (_) {
                result = false;
            }
            const ret = result;
            return ret;
        },
        __wbg_instanceof_Response_ee1d54d79ae41977: function(arg0) {
            let result;
            try {
                result = getObject(arg0) instanceof Response;
            } catch (_) {
                result = false;
            }
            const ret = result;
            return ret;
        },
        __wbg_instanceof_Uint8Array_9b9075935c74707c: function(arg0) {
            let result;
            try {
                result = getObject(arg0) instanceof Uint8Array;
            } catch (_) {
                result = false;
            }
            const ret = result;
            return ret;
        },
        __wbg_instanceof_Window_ed49b2db8df90359: function(arg0) {
            let result;
            try {
                result = getObject(arg0) instanceof Window;
            } catch (_) {
                result = false;
            }
            const ret = result;
            return ret;
        },
        __wbg_json_d214c3d336140979: function() { return handleError(function (arg0) {
            const ret = getObject(arg0).json();
            return addHeapObject(ret);
        }, arguments); },
        __wbg_length_32ed9a279acd054c: function(arg0) {
            const ret = getObject(arg0).length;
            return ret;
        },
        __wbg_log_6b5ca2e6124b2808: function(arg0) {
            console.log(getObject(arg0));
        },
        __wbg_msCrypto_d562bbe83e0d4b91: function(arg0) {
            const ret = getObject(arg0).msCrypto;
            return addHeapObject(ret);
        },
        __wbg_new_361308b2356cecd0: function() {
            const ret = new Object();
            return addHeapObject(ret);
        },
        __wbg_new_3eb36ae241fe6f44: function() {
            const ret = new Array();
            return addHeapObject(ret);
        },
        __wbg_new_b5d9e2fb389fef91: function(arg0, arg1) {
            try {
                var state0 = {a: arg0, b: arg1};
                var cb0 = (arg0, arg1) => {
                    const a = state0.a;
                    state0.a = 0;
                    try {
                        return __wasm_bindgen_func_elem_982(a, state0.b, arg0, arg1);
                    } finally {
                        state0.a = a;
                    }
                };
                const ret = new Promise(cb0);
                return addHeapObject(ret);
            } finally {
                state0.a = state0.b = 0;
            }
        },
        __wbg_new_dca287b076112a51: function() {
            const ret = new Map();
            return addHeapObject(ret);
        },
        __wbg_new_dd2b680c8bf6ae29: function(arg0) {
            const ret = new Uint8Array(getObject(arg0));
            return addHeapObject(ret);
        },
        __wbg_new_no_args_1c7c842f08d00ebb: function(arg0, arg1) {
            const ret = new Function(getStringFromWasm0(arg0, arg1));
            return addHeapObject(ret);
        },
        __wbg_new_with_length_a2c39cbe88fd8ff1: function(arg0) {
            const ret = new Uint8Array(arg0 >>> 0);
            return addHeapObject(ret);
        },
        __wbg_new_with_str_and_init_a61cbc6bdef21614: function() { return handleError(function (arg0, arg1, arg2) {
            const ret = new Request(getStringFromWasm0(arg0, arg1), getObject(arg2));
            return addHeapObject(ret);
        }, arguments); },
        __wbg_node_e1f24f89a7336c2e: function(arg0) {
            const ret = getObject(arg0).node;
            return addHeapObject(ret);
        },
        __wbg_ok_87f537440a0acf85: function(arg0) {
            const ret = getObject(arg0).ok;
            return ret;
        },
        __wbg_process_3975fd6c72f520aa: function(arg0) {
            const ret = getObject(arg0).process;
            return addHeapObject(ret);
        },
        __wbg_prototypesetcall_bdcdcc5842e4d77d: function(arg0, arg1, arg2) {
            Uint8Array.prototype.set.call(getArrayU8FromWasm0(arg0, arg1), getObject(arg2));
        },
        __wbg_queueMicrotask_0aa0a927f78f5d98: function(arg0) {
            const ret = getObject(arg0).queueMicrotask;
            return addHeapObject(ret);
        },
        __wbg_queueMicrotask_5bb536982f78a56f: function(arg0) {
            queueMicrotask(getObject(arg0));
        },
        __wbg_randomFillSync_f8c153b79f285817: function() { return handleError(function (arg0, arg1) {
            getObject(arg0).randomFillSync(takeObject(arg1));
        }, arguments); },
        __wbg_require_b74f47fc2d022fd6: function() { return handleError(function () {
            const ret = module.require;
            return addHeapObject(ret);
        }, arguments); },
        __wbg_resolve_002c4b7d9d8f6b64: function(arg0) {
            const ret = Promise.resolve(getObject(arg0));
            return addHeapObject(ret);
        },
        __wbg_set_1eb0999cf5d27fc8: function(arg0, arg1, arg2) {
            const ret = getObject(arg0).set(getObject(arg1), getObject(arg2));
            return addHeapObject(ret);
        },
        __wbg_set_3f1d0b984ed272ed: function(arg0, arg1, arg2) {
            getObject(arg0)[takeObject(arg1)] = takeObject(arg2);
        },
        __wbg_set_body_9a7e00afe3cfe244: function(arg0, arg1) {
            getObject(arg0).body = getObject(arg1);
        },
        __wbg_set_db769d02949a271d: function() { return handleError(function (arg0, arg1, arg2, arg3, arg4) {
            getObject(arg0).set(getStringFromWasm0(arg1, arg2), getStringFromWasm0(arg3, arg4));
        }, arguments); },
        __wbg_set_f43e577aea94465b: function(arg0, arg1, arg2) {
            getObject(arg0)[arg1 >>> 0] = takeObject(arg2);
        },
        __wbg_set_method_c3e20375f5ae7fac: function(arg0, arg1, arg2) {
            getObject(arg0).method = getStringFromWasm0(arg1, arg2);
        },
        __wbg_set_mode_b13642c312648202: function(arg0, arg1) {
            getObject(arg0).mode = __wbindgen_enum_RequestMode[arg1];
        },
        __wbg_static_accessor_GLOBAL_12837167ad935116: function() {
            const ret = typeof global === 'undefined' ? null : global;
            return isLikeNone(ret) ? 0 : addHeapObject(ret);
        },
        __wbg_static_accessor_GLOBAL_THIS_e628e89ab3b1c95f: function() {
            const ret = typeof globalThis === 'undefined' ? null : globalThis;
            return isLikeNone(ret) ? 0 : addHeapObject(ret);
        },
        __wbg_static_accessor_SELF_a621d3dfbb60d0ce: function() {
            const ret = typeof self === 'undefined' ? null : self;
            return isLikeNone(ret) ? 0 : addHeapObject(ret);
        },
        __wbg_static_accessor_WINDOW_f8727f0cf888e0bd: function() {
            const ret = typeof window === 'undefined' ? null : window;
            return isLikeNone(ret) ? 0 : addHeapObject(ret);
        },
        __wbg_status_89d7e803db911ee7: function(arg0) {
            const ret = getObject(arg0).status;
            return ret;
        },
        __wbg_subarray_a96e1fef17ed23cb: function(arg0, arg1, arg2) {
            const ret = getObject(arg0).subarray(arg1 >>> 0, arg2 >>> 0);
            return addHeapObject(ret);
        },
        __wbg_text_083b8727c990c8c0: function() { return handleError(function (arg0) {
            const ret = getObject(arg0).text();
            return addHeapObject(ret);
        }, arguments); },
        __wbg_then_0d9fe2c7b1857d32: function(arg0, arg1, arg2) {
            const ret = getObject(arg0).then(getObject(arg1), getObject(arg2));
            return addHeapObject(ret);
        },
        __wbg_then_b9e7b3b5f1a9e1b5: function(arg0, arg1) {
            const ret = getObject(arg0).then(getObject(arg1));
            return addHeapObject(ret);
        },
        __wbg_versions_4e31226f5e8dc909: function(arg0) {
            const ret = getObject(arg0).versions;
            return addHeapObject(ret);
        },
        __wbg_warn_f7ae1b2e66ccb930: function(arg0) {
            console.warn(getObject(arg0));
        },
        __wbindgen_cast_0000000000000001: function(arg0, arg1) {
            // Cast intrinsic for `Closure(Closure { dtor_idx: 100, function: Function { arguments: [Externref], shim_idx: 101, ret: Unit, inner_ret: Some(Unit) }, mutable: true }) -> Externref`.
            const ret = makeMutClosure(arg0, arg1, wasm.__wasm_bindgen_func_elem_694, __wasm_bindgen_func_elem_695);
            return addHeapObject(ret);
        },
        __wbindgen_cast_0000000000000002: function(arg0) {
            // Cast intrinsic for `F64 -> Externref`.
            const ret = arg0;
            return addHeapObject(ret);
        },
        __wbindgen_cast_0000000000000003: function(arg0) {
            // Cast intrinsic for `I64 -> Externref`.
            const ret = arg0;
            return addHeapObject(ret);
        },
        __wbindgen_cast_0000000000000004: function(arg0, arg1) {
            // Cast intrinsic for `Ref(Slice(U8)) -> NamedExternref("Uint8Array")`.
            const ret = getArrayU8FromWasm0(arg0, arg1);
            return addHeapObject(ret);
        },
        __wbindgen_cast_0000000000000005: function(arg0, arg1) {
            // Cast intrinsic for `Ref(String) -> Externref`.
            const ret = getStringFromWasm0(arg0, arg1);
            return addHeapObject(ret);
        },
        __wbindgen_cast_0000000000000006: function(arg0) {
            // Cast intrinsic for `U64 -> Externref`.
            const ret = BigInt.asUintN(64, arg0);
            return addHeapObject(ret);
        },
        __wbindgen_object_clone_ref: function(arg0) {
            const ret = getObject(arg0);
            return addHeapObject(ret);
        },
        __wbindgen_object_drop_ref: function(arg0) {
            takeObject(arg0);
        },
    };
    return {
        __proto__: null,
        "./wallet_wasm_bg.js": import0,
    };
}

function __wasm_bindgen_func_elem_695(arg0, arg1, arg2) {
    wasm.__wasm_bindgen_func_elem_695(arg0, arg1, addHeapObject(arg2));
}

function __wasm_bindgen_func_elem_982(arg0, arg1, arg2, arg3) {
    wasm.__wasm_bindgen_func_elem_982(arg0, arg1, addHeapObject(arg2), addHeapObject(arg3));
}


const __wbindgen_enum_RequestMode = ["same-origin", "no-cors", "cors", "navigate"];

function addHeapObject(obj) {
    if (heap_next === heap.length) heap.push(heap.length + 1);
    const idx = heap_next;
    heap_next = heap[idx];

    heap[idx] = obj;
    return idx;
}

const CLOSURE_DTORS = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(state => state.dtor(state.a, state.b));

function debugString(val) {
    // primitive types
    const type = typeof val;
    if (type == 'number' || type == 'boolean' || val == null) {
        return  `${val}`;
    }
    if (type == 'string') {
        return `"${val}"`;
    }
    if (type == 'symbol') {
        const description = val.description;
        if (description == null) {
            return 'Symbol';
        } else {
            return `Symbol(${description})`;
        }
    }
    if (type == 'function') {
        const name = val.name;
        if (typeof name == 'string' && name.length > 0) {
            return `Function(${name})`;
        } else {
            return 'Function';
        }
    }
    // objects
    if (Array.isArray(val)) {
        const length = val.length;
        let debug = '[';
        if (length > 0) {
            debug += debugString(val[0]);
        }
        for(let i = 1; i < length; i++) {
            debug += ', ' + debugString(val[i]);
        }
        debug += ']';
        return debug;
    }
    // Test for built-in
    const builtInMatches = /\[object ([^\]]+)\]/.exec(toString.call(val));
    let className;
    if (builtInMatches && builtInMatches.length > 1) {
        className = builtInMatches[1];
    } else {
        // Failed to match the standard '[object ClassName]'
        return toString.call(val);
    }
    if (className == 'Object') {
        // we're a user defined class or Object
        // JSON.stringify avoids problems with cycles, and is generally much
        // easier than looping through ownProperties of `val`.
        try {
            return 'Object(' + JSON.stringify(val) + ')';
        } catch (_) {
            return 'Object';
        }
    }
    // errors
    if (val instanceof Error) {
        return `${val.name}: ${val.message}\n${val.stack}`;
    }
    // TODO we could test for more things here, like `Set`s and `Map`s.
    return className;
}

function dropObject(idx) {
    if (idx < 132) return;
    heap[idx] = heap_next;
    heap_next = idx;
}

function getArrayU8FromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    return getUint8ArrayMemory0().subarray(ptr / 1, ptr / 1 + len);
}

let cachedDataViewMemory0 = null;
function getDataViewMemory0() {
    if (cachedDataViewMemory0 === null || cachedDataViewMemory0.buffer.detached === true || (cachedDataViewMemory0.buffer.detached === undefined && cachedDataViewMemory0.buffer !== wasm.memory.buffer)) {
        cachedDataViewMemory0 = new DataView(wasm.memory.buffer);
    }
    return cachedDataViewMemory0;
}

function getStringFromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    return decodeText(ptr, len);
}

let cachedUint8ArrayMemory0 = null;
function getUint8ArrayMemory0() {
    if (cachedUint8ArrayMemory0 === null || cachedUint8ArrayMemory0.byteLength === 0) {
        cachedUint8ArrayMemory0 = new Uint8Array(wasm.memory.buffer);
    }
    return cachedUint8ArrayMemory0;
}

function getObject(idx) { return heap[idx]; }

function handleError(f, args) {
    try {
        return f.apply(this, args);
    } catch (e) {
        wasm.__wbindgen_export3(addHeapObject(e));
    }
}

let heap = new Array(128).fill(undefined);
heap.push(undefined, null, true, false);

let heap_next = heap.length;

function isLikeNone(x) {
    return x === undefined || x === null;
}

function makeMutClosure(arg0, arg1, dtor, f) {
    const state = { a: arg0, b: arg1, cnt: 1, dtor };
    const real = (...args) => {

        // First up with a closure we increment the internal reference
        // count. This ensures that the Rust closure environment won't
        // be deallocated while we're invoking it.
        state.cnt++;
        const a = state.a;
        state.a = 0;
        try {
            return f(a, state.b, ...args);
        } finally {
            state.a = a;
            real._wbg_cb_unref();
        }
    };
    real._wbg_cb_unref = () => {
        if (--state.cnt === 0) {
            state.dtor(state.a, state.b);
            state.a = 0;
            CLOSURE_DTORS.unregister(state);
        }
    };
    CLOSURE_DTORS.register(real, state, state);
    return real;
}

function passStringToWasm0(arg, malloc, realloc) {
    if (realloc === undefined) {
        const buf = cachedTextEncoder.encode(arg);
        const ptr = malloc(buf.length, 1) >>> 0;
        getUint8ArrayMemory0().subarray(ptr, ptr + buf.length).set(buf);
        WASM_VECTOR_LEN = buf.length;
        return ptr;
    }

    let len = arg.length;
    let ptr = malloc(len, 1) >>> 0;

    const mem = getUint8ArrayMemory0();

    let offset = 0;

    for (; offset < len; offset++) {
        const code = arg.charCodeAt(offset);
        if (code > 0x7F) break;
        mem[ptr + offset] = code;
    }
    if (offset !== len) {
        if (offset !== 0) {
            arg = arg.slice(offset);
        }
        ptr = realloc(ptr, len, len = offset + arg.length * 3, 1) >>> 0;
        const view = getUint8ArrayMemory0().subarray(ptr + offset, ptr + len);
        const ret = cachedTextEncoder.encodeInto(arg, view);

        offset += ret.written;
        ptr = realloc(ptr, len, offset, 1) >>> 0;
    }

    WASM_VECTOR_LEN = offset;
    return ptr;
}

function takeObject(idx) {
    const ret = getObject(idx);
    dropObject(idx);
    return ret;
}

let cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true });
cachedTextDecoder.decode();
const MAX_SAFARI_DECODE_BYTES = 2146435072;
let numBytesDecoded = 0;
function decodeText(ptr, len) {
    numBytesDecoded += len;
    if (numBytesDecoded >= MAX_SAFARI_DECODE_BYTES) {
        cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true });
        cachedTextDecoder.decode();
        numBytesDecoded = len;
    }
    return cachedTextDecoder.decode(getUint8ArrayMemory0().subarray(ptr, ptr + len));
}

const cachedTextEncoder = new TextEncoder();

if (!('encodeInto' in cachedTextEncoder)) {
    cachedTextEncoder.encodeInto = function (arg, view) {
        const buf = cachedTextEncoder.encode(arg);
        view.set(buf);
        return {
            read: arg.length,
            written: buf.length
        };
    };
}

let WASM_VECTOR_LEN = 0;

let wasmModule, wasm;
function __wbg_finalize_init(instance, module) {
    wasm = instance.exports;
    wasmModule = module;
    cachedDataViewMemory0 = null;
    cachedUint8ArrayMemory0 = null;
    return wasm;
}

async function __wbg_load(module, imports) {
    if (typeof Response === 'function' && module instanceof Response) {
        if (typeof WebAssembly.instantiateStreaming === 'function') {
            try {
                return await WebAssembly.instantiateStreaming(module, imports);
            } catch (e) {
                const validResponse = module.ok && expectedResponseType(module.type);

                if (validResponse && module.headers.get('Content-Type') !== 'application/wasm') {
                    console.warn("`WebAssembly.instantiateStreaming` failed because your server does not serve Wasm with `application/wasm` MIME type. Falling back to `WebAssembly.instantiate` which is slower. Original error:\n", e);

                } else { throw e; }
            }
        }

        const bytes = await module.arrayBuffer();
        return await WebAssembly.instantiate(bytes, imports);
    } else {
        const instance = await WebAssembly.instantiate(module, imports);

        if (instance instanceof WebAssembly.Instance) {
            return { instance, module };
        } else {
            return instance;
        }
    }

    function expectedResponseType(type) {
        switch (type) {
            case 'basic': case 'cors': case 'default': return true;
        }
        return false;
    }
}

function initSync(module) {
    if (wasm !== undefined) return wasm;


    if (module !== undefined) {
        if (Object.getPrototypeOf(module) === Object.prototype) {
            ({module} = module)
        } else {
            console.warn('using deprecated parameters for `initSync()`; pass a single object instead')
        }
    }

    const imports = __wbg_get_imports();
    if (!(module instanceof WebAssembly.Module)) {
        module = new WebAssembly.Module(module);
    }
    const instance = new WebAssembly.Instance(module, imports);
    return __wbg_finalize_init(instance, module);
}

async function __wbg_init(module_or_path) {
    if (wasm !== undefined) return wasm;


    if (module_or_path !== undefined) {
        if (Object.getPrototypeOf(module_or_path) === Object.prototype) {
            ({module_or_path} = module_or_path)
        } else {
            console.warn('using deprecated parameters for the initialization function; pass a single object instead')
        }
    }

    if (module_or_path === undefined) {
        module_or_path = new URL('wallet_wasm_bg.wasm', import.meta.url);
    }
    const imports = __wbg_get_imports();

    if (typeof module_or_path === 'string' || (typeof Request === 'function' && module_or_path instanceof Request) || (typeof URL === 'function' && module_or_path instanceof URL)) {
        module_or_path = fetch(module_or_path);
    }

    const { instance, module } = await __wbg_load(await module_or_path, imports);

    return __wbg_finalize_init(instance, module);
}

export { initSync, __wbg_init as default };
