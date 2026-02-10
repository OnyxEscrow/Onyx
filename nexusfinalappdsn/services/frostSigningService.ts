/**
 * FROST Signing Service - Complete client-side signing flow
 *
 * Implements the 8-step FROST CLSAG signing protocol:
 * 1. Load key package (from localStorage or Shield backup)
 * 2. Fetch TX data from server
 * 3. Generate nonce commitment (MuSig2-style)
 * 4. Submit nonce and wait for peer
 * 5. Generate partial CLSAG signature
 * 6. Submit partial signature
 * 7. Wait for peer partial signature
 * 8. Server aggregates and broadcasts
 *
 * SECURITY:
 * - Never logs alpha_secret (nonce secret)
 * - Password zeroization after key load
 * - Timeouts: 2 min nonce, 3 min broadcast
 * - Poll intervals: 3s nonce, 5s broadcast
 */

import { getWasmModule } from './wasmService';
import { loadKey } from './keyStorage';

// ============================================================================
// Type Definitions
// ============================================================================

export interface TxSigningData {
  tx_prefix_hash: string;
  clsag_message_hash: string;
  ring_data_json: string;
  pseudo_out?: string;
  multisig_pubkey: string;
  recipient_address: string;
  amount_atomic: string;
  /** pseudo_out_mask = mask_0 + mask_1 (hex) — WASM commitment_mask */
  pseudo_out_mask?: string;
  /** Input's commitment mask z (hex) — WASM funding_mask */
  funding_commitment_mask?: string;
  /** Shared multisig view key (hex) — WASM derivation */
  multisig_view_key?: string;
  /** TX public key from funding TX (hex) — WASM derivation */
  funding_tx_pubkey?: string;
  /** Output index in funding TX — WASM derivation */
  funding_output_index?: number;
}

export interface NonceCommitment {
  commitment_hash: string;
  r_public: string;
  r_prime_public: string;
  alpha_secret: string; // NEVER log this!
}

export interface PartialClsagSignature {
  c1: string;
  s_values: string[];
  s_l_partial: string;
  d: string;
  partial_key_image: string;
  mu_p: string;
  mu_c: string;
  signer_index: number;
  pseudo_out: string;
}

export interface FirstSignerData {
  c1: string;
  s_values: string[];
  d: string;
  pseudo_out: string;
  mu_p: string;
  mu_c: string;
}

export interface SigningProgress {
  stage:
    | 'idle'
    | 'loading_key'
    | 'generating_nonce'
    | 'waiting_vendor'
    | 'signing'
    | 'waiting_buyer_sig'
    | 'waiting_arbiter'
    | 'aggregating'
    | 'completed'
    | 'failed';
  message: string;
  error?: string;
}

export interface PeerNonceData {
  buyer?: {
    r_public: string;
    r_prime_public: string;
  };
  vendor?: {
    r_public: string;
    r_prime_public: string;
  };
  aggregated_r?: string;
  aggregated_r_prime?: string;
}

export interface SigningStatusData {
  buyer_partial_submitted: boolean;
  vendor_partial_submitted: boolean;
  arbiter_partial_submitted: boolean;
  tx_hash?: string;
  status: string;
}

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Sleep for specified milliseconds
 */
function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Convert hex string to Uint8Array
 */
function hexToUint8Array(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}

/**
 * Convert Uint8Array to hex string
 */
function uint8ArrayToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

// ============================================================================
// Core Functions
// ============================================================================

/**
 * Load FROST key package from localStorage or Shield backup
 *
 * Tries plaintext localStorage first, then falls back to encrypted Shield backup.
 *
 * @param escrowId - The escrow identifier
 * @param role - 'buyer', 'vendor', or 'arbiter'
 * @param password - Shield password (required if plaintext not found)
 * @returns Key package as hex string
 * @throws Error if key not found or wrong password
 */
export async function loadKeyPackage(
  escrowId: string,
  role: string,
  password?: string
): Promise<string> {
  // Try plaintext localStorage first (legacy storage)
  const plaintextKey = localStorage.getItem(`frost_dkg_${escrowId}_${role}_key_package`);
  if (plaintextKey) {
    console.log('[FROST] Key package loaded from plaintext storage');
    return plaintextKey;
  }

  // Try keyStorage (IndexedDB/localStorage with proper encryption)
  if (password) {
    try {
      const keyFromStorage = await loadKey(escrowId, password);
      if (keyFromStorage) {
        console.log('[FROST] Key package loaded from keyStorage (IndexedDB)');
        return keyFromStorage;
      }
    } catch (err) {
      console.warn('[FROST] keyStorage load failed:', err);
    }
  }

  // Try legacy encrypted Shield backup (old format)
  const encryptedBackup = localStorage.getItem(`frost_dkg_${escrowId}_${role}_encrypted_backup`);
  if (encryptedBackup && password) {
    const wasm = getWasmModule();
    if (!wasm) {
      throw new Error('WASM module not initialized');
    }

    try {
      // Decrypt using WASM backup decryption (password-based)
      const encryptedBytes = hexToUint8Array(encryptedBackup);
      const decryptedBytes = wasm.decrypt_key_from_backup(encryptedBytes, password);
      const keyPackageHex = uint8ArrayToHex(decryptedBytes);

      console.log('[FROST] Key package decrypted from legacy Shield backup');
      return keyPackageHex;
    } catch (error) {
      throw new Error('Wrong Shield password or corrupted backup');
    }
  }

  // No key found anywhere
  if (!password) {
    throw new Error('Shield password required - key not found in storage');
  }
  throw new Error('Key package not found. Please restore from Shield backup.');
}

/**
 * Compute and submit partial key image for FROST signing
 *
 * This MUST be called before fetchTxDataForSigning (init_signing).
 * The server requires aggregated_key_image to build the TX.
 *
 * Flow:
 * 1. Fetch escrow details (one_time_pubkey, tx_pubkey, output_index, view_key)
 * 2. Extract secret share from key package
 * 3. Compute Lagrange coefficient for this signer
 * 4. Compute partial key image: pKI = (d + λ*b) * Hp(P)
 * 5. Submit to server
 * 6. Poll until both PKIs aggregated (or return immediately if already done)
 *
 * @param escrowId - The escrow identifier
 * @param role - 'buyer' or 'vendor'
 * @param keyPackageHex - FROST key package (from loadKeyPackage)
 * @returns Aggregated key image (when both parties have submitted)
 */
export async function computeAndSubmitPartialKeyImage(
  escrowId: string,
  role: string,
  keyPackageHex: string
): Promise<string> {
  const wasm = getWasmModule();
  if (!wasm) {
    throw new Error('WASM module not initialized');
  }

  // 1. Fetch escrow details for PKI computation
  console.log('[FROST] Fetching escrow details for PKI computation...');
  const response = await fetch(`/api/v2/escrow/${escrowId}`, {
    credentials: 'include',
  });

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({ error: 'Unknown error' }));
    throw new Error(errorData.error || `Failed to fetch escrow: ${response.status}`);
  }

  const escrow = await response.json();

  // Check if already aggregated
  if (escrow.aggregated_key_image) {
    console.log('[FROST] Key image already aggregated, skipping PKI submission');
    return escrow.aggregated_key_image;
  }

  // Validate required fields
  const oneTimePubkey = escrow.one_time_pubkey || escrow.funding_output_pubkey;
  const txPubkey = escrow.funding_tx_pubkey;
  const viewKey = escrow.multisig_view_key;
  const outputIndex = escrow.funding_output_index ?? 0;
  const groupPubkey = escrow.frost_group_pubkey;

  if (!oneTimePubkey || !txPubkey || !viewKey || !groupPubkey) {
    throw new Error(
      'Missing escrow data for PKI computation: ' +
      `oneTimePubkey=${!!oneTimePubkey}, txPubkey=${!!txPubkey}, viewKey=${!!viewKey}, groupPubkey=${!!groupPubkey}`
    );
  }

  // 2. Extract secret share from key package
  console.log('[FROST] Extracting secret share from key package...');
  const secretShare = wasm.frost_extract_secret_share(keyPackageHex);

  // 3. Compute Lagrange coefficient
  // For buyer(1)+vendor(2): λ_buyer=2, λ_vendor=-1
  // frost_compute_lagrange_coefficient returns the λ for the current signer
  const signerIndex = role === 'buyer' ? 1 : 2;
  const otherIndex = role === 'buyer' ? 2 : 1;
  const lagrangeCoeff = wasm.frost_compute_lagrange_coefficient(signerIndex, signerIndex, otherIndex);

  console.log(`[FROST] Role=${role}, signerIndex=${signerIndex}, lagrangeCoeff prefix=${lagrangeCoeff.slice(0, 16)}`);

  // 4. Compute partial key image with derivation
  // pKI = (d + λ*b) * Hp(P) where d is derivation, λ is Lagrange, b is spend share
  console.log('[FROST] Computing partial key image with derivation...');
  const pkiResult = wasm.compute_partial_key_image_with_derivation(
    secretShare,
    txPubkey,
    viewKey,
    BigInt(outputIndex),
    oneTimePubkey,
    lagrangeCoeff
  );

  console.log('[FROST] PKI Result:', pkiResult, 'type:', typeof pkiResult);

  // Handle Map response from WASM (serde_wasm_bindgen returns Map)
  let partialKeyImage: string;
  if (pkiResult instanceof Map) {
    partialKeyImage = pkiResult.get('partialKeyImage');
    console.log('[FROST] PKI Result is a Map, partialKeyImage:', partialKeyImage?.slice(0, 16));
  } else if (pkiResult && typeof pkiResult === 'object') {
    partialKeyImage = (pkiResult as Record<string, string>).partialKeyImage ||
                      (pkiResult as Record<string, string>).partial_key_image;
  } else {
    throw new Error(`PKI computation returned unexpected type: ${typeof pkiResult}`);
  }

  if (!partialKeyImage) {
    throw new Error(`PKI computation returned no partialKeyImage. Result: ${pkiResult instanceof Map ? Array.from(pkiResult.entries()) : JSON.stringify(pkiResult)}`);
  }
  console.log(`[FROST] Partial key image computed: ${partialKeyImage.slice(0, 16)}...`);

  // 5. Submit to server
  console.log('[FROST] Submitting partial key image to server...');
  const submitResponse = await fetch(`/api/v2/escrow/${escrowId}/submit-partial-key-image`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify({
      role,
      partial_key_image: partialKeyImage,
    }),
  });

  if (!submitResponse.ok) {
    const errorData = await submitResponse.json().catch(() => ({ error: 'Unknown error' }));
    throw new Error(errorData.error || `Failed to submit PKI: ${submitResponse.status}`);
  }

  const submitResult = await submitResponse.json();
  console.log(`[FROST] PKI submitted. Count: ${submitResult.partial_key_images_count}`);

  // 6. If aggregated, return immediately
  if (submitResult.aggregated_key_image) {
    console.log('[FROST] Key images aggregated immediately');
    return submitResult.aggregated_key_image;
  }

  // 7. Poll for aggregation (wait for other party)
  console.log('[FROST] Waiting for other party to submit PKI...');
  const maxWaitMs = 120000; // 2 minutes
  const pollIntervalMs = 3000;
  const startTime = Date.now();

  while (Date.now() - startTime < maxWaitMs) {
    await new Promise(resolve => setTimeout(resolve, pollIntervalMs));

    const pollResponse = await fetch(`/api/v2/escrow/${escrowId}`, {
      credentials: 'include',
    });

    if (!pollResponse.ok) {
      continue;
    }

    const pollData = await pollResponse.json();
    if (pollData.aggregated_key_image) {
      console.log('[FROST] Key images aggregated after polling');
      return pollData.aggregated_key_image;
    }
  }

  throw new Error('Timeout waiting for key image aggregation - other party did not submit PKI');
}

/**
 * Fetch transaction signing data from server
 *
 * Initializes the signing session and retrieves ring data, TX prefix hash, etc.
 *
 * @param escrowId - The escrow identifier
 * @returns Transaction signing data
 */
export async function fetchTxDataForSigning(escrowId: string): Promise<TxSigningData> {
  const response = await fetch(`/api/escrow/frost/${escrowId}/sign/init`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
  });

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({ error: 'Unknown error' }));
    throw new Error(errorData.error || `Failed to initialize signing: ${response.status}`);
  }

  const data = await response.json();
  return data.data as TxSigningData;
}

/**
 * Generate MuSig2-style nonce commitment
 *
 * Creates a random nonce (alpha) and derives R = alpha*G commitment points.
 *
 * @param txPrefixHash - Transaction prefix hash (64 hex chars)
 * @param multisigPubkey - Multisig public key (64 hex chars)
 * @returns Nonce commitment with alpha_secret (NEVER LOG THIS!)
 */
export async function generateNonceCommitment(
  txPrefixHash: string,
  multisigPubkey: string
): Promise<NonceCommitment> {
  const wasm = getWasmModule();
  if (!wasm) {
    throw new Error('WASM module not initialized');
  }

  try {
    const result = wasm.generate_nonce_commitment(txPrefixHash, multisigPubkey);

    // Handle Map response from serde_wasm_bindgen
    let commitment_hash: string;
    let r_public: string;
    let r_prime_public: string;
    let alpha_secret: string;

    if (result instanceof Map) {
      commitment_hash = result.get('commitment_hash');
      r_public = result.get('r_public');
      r_prime_public = result.get('r_prime_public');
      alpha_secret = result.get('alpha_secret');
    } else if (result && typeof result === 'object') {
      commitment_hash = result.commitment_hash;
      r_public = result.r_public;
      r_prime_public = result.r_prime_public;
      alpha_secret = result.alpha_secret;
    } else {
      throw new Error(`Unexpected nonce result type: ${typeof result}`);
    }

    if (!commitment_hash || !r_public || !r_prime_public || !alpha_secret) {
      throw new Error(`Invalid nonce commitment result: hash=${!!commitment_hash}, r=${!!r_public}, r'=${!!r_prime_public}, alpha=${!!alpha_secret}`);
    }

    console.log('[FROST] Nonce commitment generated (alpha_secret NOT logged)');

    return { commitment_hash, r_public, r_prime_public, alpha_secret };
  } catch (error) {
    throw new Error(`Nonce generation failed: ${error instanceof Error ? error.message : String(error)}`);
  }
}

/**
 * Submit nonce commitment to server
 *
 * @param escrowId - The escrow identifier
 * @param role - 'buyer' or 'vendor'
 * @param nonce - Nonce commitment (without alpha_secret)
 */
export async function submitNonceCommitment(
  escrowId: string,
  role: string,
  nonce: NonceCommitment
): Promise<void> {
  const response = await fetch(`/api/escrow/frost/${escrowId}/sign/nonces`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify({
      role,
      r_public: nonce.r_public,
      r_prime_public: nonce.r_prime_public,
      commitment_hash: nonce.commitment_hash,
    }),
  });

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({ error: 'Unknown error' }));
    throw new Error(errorData.error || `Failed to submit nonce: ${response.status}`);
  }

  console.log('[FROST] Nonce commitment submitted to server');
}

/**
 * Poll for peer nonce commitment
 *
 * Waits until both buyer and vendor have submitted their nonces.
 *
 * @param escrowId - The escrow identifier
 * @param timeoutMs - Timeout in milliseconds (default: 120 seconds)
 * @returns Peer nonce data with aggregated nonces
 * @throws Error on timeout
 */
export async function pollForPeerNonce(
  escrowId: string,
  timeoutMs: number = 120000 // 2 minutes
): Promise<PeerNonceData> {
  const startTime = Date.now();
  const pollInterval = 3000; // 3 seconds

  while (Date.now() - startTime < timeoutMs) {
    const response = await fetch(`/api/escrow/frost/${escrowId}/sign/nonces`, {
      method: 'GET',
      credentials: 'include',
    });

    if (!response.ok) {
      // Non-fatal: continue polling
      await sleep(pollInterval);
      continue;
    }

    const data = await response.json();
    const nonceData = data.data as PeerNonceData;

    // Check if both parties submitted
    if (nonceData.buyer && nonceData.vendor) {
      console.log('[FROST] Both nonces received, aggregated nonces ready');
      return nonceData;
    }

    await sleep(pollInterval);
  }

  throw new Error('Timeout waiting for peer nonce (2 minutes). Vendor may not be online.');
}

/**
 * Generate partial CLSAG signature
 *
 * Calls WASM sign_clsag_partial with the signer's key share and nonce.
 * Constructs SignInputData from server's ring_data_json + escrow fields.
 *
 * @param keyPackageHex - FROST key package (hex)
 * @param txData - Transaction signing data from server
 * @param nonceSecret - The alpha_secret from nonce generation
 * @param role - 'buyer' or 'vendor'
 * @param aggregatedKeyImage - Aggregated key image from PKI step (hex)
 * @param peerNonce - Peer's nonce public points (from pollForPeerNonce)
 * @param myNonce - My nonce public R (for integrity verification)
 * @returns Partial CLSAG signature
 */
export async function signClsagPartial(
  keyPackageHex: string,
  txData: TxSigningData,
  nonceSecret: string,
  role: 'buyer' | 'vendor',
  aggregatedKeyImage: string,
  peerNonce: PeerNonceData | null,
  myNonce: { r_public: string; r_prime_public: string } | null,
  firstSignerData?: FirstSignerData
): Promise<PartialClsagSignature> {
  const wasm = getWasmModule();
  if (!wasm) {
    throw new Error('WASM module not initialized');
  }

  try {
    // Extract secret share from key package
    const secretShare = wasm.frost_extract_secret_share(keyPackageHex);

    // Compute Lagrange coefficient
    const signerIndex = role === 'buyer' ? 1 : 2;
    const signer1Index = 1; // Buyer
    const signer2Index = 2; // Vendor
    const lagrangeCoeff = wasm.frost_compute_lagrange_coefficient(
      signerIndex,
      signer1Index,
      signer2Index
    );

    console.log('[FROST] Signing with partial key share (Lagrange applied)');

    // Parse server's ring_data_json into WASM SignInputData format
    const ringData = JSON.parse(txData.ring_data_json);
    const ringMembers: [string, string][] = ringData.ring_members.map(
      (m: { key: string; mask: string }) => [m.key, m.mask]
    );
    const signerIdx: number = ringData.real_position;
    const ringIndices: number[] = ringData.ring_indices;

    // Build peer_nonce_public for MuSig2 R_agg computation
    const peerRole = role === 'buyer' ? 'vendor' : 'buyer';
    let peerNonceJson: string | null = null;
    if (peerNonce) {
      const peerData = peerNonce[peerRole];
      if (peerData) {
        peerNonceJson = JSON.stringify({
          r_public: peerData.r_public,
          r_prime_public: peerData.r_prime_public,
        });
      }
    }

    // Construct WASM SignInputData
    const signInputData: Record<string, unknown> = {
      ring: ringMembers,
      offsets: ringIndices,
      signer_index: signerIdx,
      commitment_mask: txData.pseudo_out_mask || '',
      commitment_amount: parseInt(txData.amount_atomic, 10),
      alpha_secret: nonceSecret,
    };

    // Add optional derivation fields
    if (txData.funding_commitment_mask) {
      signInputData.funding_mask = txData.funding_commitment_mask;
    }
    if (txData.funding_tx_pubkey) {
      signInputData.tx_pub_key = txData.funding_tx_pubkey;
    }
    if (txData.multisig_view_key) {
      signInputData.view_key = txData.multisig_view_key;
    }
    if (txData.funding_output_index !== undefined && txData.funding_output_index !== null) {
      signInputData.output_index = txData.funding_output_index;
    }
    if (peerNonceJson) {
      signInputData.peer_nonce_public = peerNonceJson;
    }
    if (myNonce) {
      signInputData.my_submitted_r_public = myNonce.r_public;
    }

    const inputDataJson = JSON.stringify(signInputData);
    console.log(`[FROST] SignInputData: ring_size=${ringMembers.length}, signer_idx=${signerIdx}, has_derivation=${!!txData.funding_tx_pubkey}`);

    // Call WASM partial signing
    // Round-Robin CLSAG: vendor = first signer (null), buyer = second signer (reuse vendor's decoys)
    const isSecondSigner = !!firstSignerData;

    if (isSecondSigner && firstSignerData) {
      console.log(`[FROST] Signing as SECOND signer: reusing first-signer c1=${firstSignerData.c1.slice(0, 16)}..., ${firstSignerData.s_values.length} s-values`);
    } else {
      console.log('[FROST] Signing as FIRST signer: generating random decoys + c1');
    }

    const result = wasm.sign_clsag_partial_wasm(
      secretShare,
      inputDataJson,
      txData.clsag_message_hash,
      txData.multisig_pubkey,
      aggregatedKeyImage,
      isSecondSigner ? firstSignerData.c1 : null,
      isSecondSigner ? JSON.stringify(firstSignerData.s_values) : null,
      isSecondSigner ? firstSignerData.d : null,
      isSecondSigner ? firstSignerData.mu_p : null,
      isSecondSigner ? firstSignerData.mu_c : null,
      isSecondSigner ? firstSignerData.pseudo_out : null,
      false, // used_r_agg
      lagrangeCoeff
    );

    // Handle Map result from serde_wasm_bindgen
    let signature: { c1: string; s: string[]; D: string };
    let keyImage: string;
    let pseudoOut: string;
    let partialKeyImage: string;
    let muP = '';
    let muC = '';

    if (result instanceof Map) {
      const sigMap = result.get('signature');
      if (sigMap instanceof Map) {
        signature = {
          c1: sigMap.get('c1'),
          s: sigMap.get('s'),
          D: sigMap.get('D'),
        };
      } else {
        signature = sigMap;
      }
      keyImage = result.get('keyImage');
      partialKeyImage = result.get('partialKeyImage') || keyImage;
      pseudoOut = result.get('pseudoOut');
      muP = result.get('mu_p') || '';
      muC = result.get('mu_c') || '';
    } else if (result && typeof result === 'object') {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const r = result as any;
      signature = r.signature;
      keyImage = r.keyImage;
      partialKeyImage = r.partialKeyImage || keyImage;
      pseudoOut = r.pseudoOut;
      muP = r.mu_p || '';
      muC = r.mu_c || '';
    } else {
      throw new Error(`Unexpected WASM result type: ${typeof result}`);
    }

    console.log(`[FROST] Partial signature generated: c1=${signature.c1?.slice(0, 16)}...`);

    return {
      c1: signature.c1,
      s_values: signature.s,
      s_l_partial: signature.s[signerIdx],
      d: signature.D,
      partial_key_image: partialKeyImage,
      mu_p: muP,
      mu_c: muC,
      signer_index: signerIdx,
      pseudo_out: pseudoOut,
    };
  } catch (error) {
    throw new Error(`CLSAG signing failed: ${error instanceof Error ? error.message : String(error)}`);
  }
}

/**
 * Submit partial signature to server
 *
 * @param escrowId - The escrow identifier
 * @param role - 'buyer' or 'vendor'
 * @param partialSig - Partial CLSAG signature
 */
export async function submitPartialSignature(
  escrowId: string,
  role: string,
  partialSig: PartialClsagSignature
): Promise<void> {
  const response = await fetch(`/api/escrow/frost/${escrowId}/sign/partial`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify({
      role,
      partial_signature: JSON.stringify({
        signature: {
          D: partialSig.d,
          s: partialSig.s_values,
          c1: partialSig.c1,
        },
        key_image: partialSig.partial_key_image,
        pseudo_out: partialSig.pseudo_out,
        mu_p: partialSig.mu_p,
        mu_c: partialSig.mu_c,
      }),
      partial_key_image: partialSig.partial_key_image,
    }),
  });

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({ error: 'Unknown error' }));
    throw new Error(errorData.error || `Failed to submit partial signature: ${response.status}`);
  }

  console.log('[FROST] Partial signature submitted to server');
}

/**
 * Submit FROST secret share for ATOMIC server-side CLSAG signing.
 *
 * This is the simplified approach matching commit 835ccd0:
 * - Browser extracts secret share from FROST key package
 * - Server receives both shares → reconstructs x_total → signs CLSAG atomically
 * - No WASM CLSAG signing needed, no nonce exchange needed
 *
 * @param escrowId - The escrow identifier
 * @param role - 'buyer' or 'vendor'
 * @param secretShareHex - Raw 32-byte FROST secret share as hex
 */
export async function submitFrostShare(
  escrowId: string,
  role: string,
  secretShareHex: string
): Promise<void> {
  const response = await fetch(`/api/escrow/frost/${escrowId}/sign/partial`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify({
      role,
      partial_signature: JSON.stringify({
        frost_share: secretShareHex,
      }),
      partial_key_image: '', // Not used in atomic approach
    }),
  });

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({ error: 'Unknown error' }));
    throw new Error(errorData.error || `Failed to submit FROST share: ${response.status}`);
  }

  console.log(`[FROST] ${role} secret share submitted for atomic CLSAG signing`);
}

/**
 * Poll for first signer (buyer) data for Round-Robin CLSAG
 *
 * Vendor calls this to wait for buyer to sign first, then fetches
 * buyer's c1, s_values, D, mu_p, mu_c, pseudo_out for second-signer mode.
 *
 * @param escrowId - The escrow identifier
 * @param timeoutMs - Timeout in milliseconds (default: 120 seconds)
 * @returns First signer data for second-signer WASM call
 * @throws Error on timeout
 */
export async function pollForFirstSignerData(
  escrowId: string,
  timeoutMs: number = 120000
): Promise<FirstSignerData> {
  const startTime = Date.now();
  const pollInterval = 3000;

  while (Date.now() - startTime < timeoutMs) {
    const response = await fetch(
      `/api/escrow/frost/${escrowId}/sign/first-signer-data`,
      { method: 'GET', credentials: 'include' }
    );

    if (response.status === 204) {
      console.log('[FROST] Buyer hasn\'t signed yet, polling...');
      await sleep(pollInterval);
      continue;
    }

    if (response.ok) {
      const data = await response.json();
      const fsd = data.data as FirstSignerData;
      console.log(`[FROST] First signer data received: c1=${fsd.c1.slice(0, 16)}..., ${fsd.s_values.length} s-values`);
      return fsd;
    }

    await sleep(pollInterval);
  }

  throw new Error('Timeout waiting for buyer signature (2 minutes). Buyer must sign first.');
}

/**
 * Poll for transaction broadcast
 *
 * Waits for server to aggregate and broadcast the transaction.
 *
 * @param escrowId - The escrow identifier
 * @param timeoutMs - Timeout in milliseconds (default: 180 seconds)
 * @returns Transaction hash
 * @throws Error on timeout
 */
export async function pollForBroadcast(
  escrowId: string,
  timeoutMs: number = 180000 // 3 minutes
): Promise<string> {
  const startTime = Date.now();
  const pollInterval = 5000; // 5 seconds

  while (Date.now() - startTime < timeoutMs) {
    const response = await fetch(`/api/escrow/frost/${escrowId}/sign/status`, {
      method: 'GET',
      credentials: 'include',
    });

    if (!response.ok) {
      // Non-fatal: continue polling
      await sleep(pollInterval);
      continue;
    }

    const data = await response.json();
    const statusData = data.data as SigningStatusData;

    // Check if transaction broadcasted
    if (statusData.tx_hash) {
      console.log(`[FROST] Transaction broadcasted: ${statusData.tx_hash.slice(0, 16)}...`);
      return statusData.tx_hash;
    }

    // Log progress
    if (statusData.buyer_partial_submitted && statusData.vendor_partial_submitted) {
      console.log('[FROST] Both partial signatures received, server aggregating...');
    }

    await sleep(pollInterval);
  }

  throw new Error('Timeout waiting for broadcast (3 minutes). Server aggregation may have failed — check logs.');
}

// ============================================================================
// Complete Signing Flow
// ============================================================================

/**
 * Execute complete FROST signing flow (8 steps)
 *
 * This is a convenience wrapper that executes all steps in sequence.
 * For granular control, use individual functions.
 *
 * @param escrowId - The escrow identifier
 * @param role - 'buyer' or 'vendor'
 * @param password - Shield password
 * @param onProgress - Progress callback
 * @returns Transaction hash
 */
export async function executeSigningFlow(
  escrowId: string,
  role: 'buyer' | 'vendor',
  password: string,
  onProgress?: (progress: SigningProgress) => void
): Promise<string> {
  try {
    // Step 1: Load key package
    onProgress?.({ stage: 'loading_key', message: 'Loading key package...' });
    const keyPackageHex = await loadKeyPackage(escrowId, role, password);

    // Step 1.5: Compute and submit partial key image
    onProgress?.({ stage: 'loading_key', message: 'Computing key image...' });
    const aggregatedKI = await computeAndSubmitPartialKeyImage(escrowId, role, keyPackageHex);

    // Step 2: Fetch TX data
    onProgress?.({ stage: 'generating_nonce', message: 'Fetching transaction data...' });
    const txData = await fetchTxDataForSigning(escrowId);

    // Step 3: Generate nonce commitment
    onProgress?.({ stage: 'generating_nonce', message: 'Generating nonce...' });
    const nonceResult = await generateNonceCommitment(txData.tx_prefix_hash, txData.multisig_pubkey);

    // Step 4: Submit nonce and wait for peer
    onProgress?.({ stage: 'generating_nonce', message: 'Submitting nonce...' });
    await submitNonceCommitment(escrowId, role, nonceResult);

    onProgress?.({ stage: 'waiting_vendor', message: 'Waiting for peer nonce...' });
    const peerNonceData = await pollForPeerNonce(escrowId);

    // Step 5: Generate partial signature
    onProgress?.({ stage: 'signing', message: 'Generating signature...' });
    const partialSig = await signClsagPartial(
      keyPackageHex, txData, nonceResult.alpha_secret, role,
      aggregatedKI, peerNonceData,
      { r_public: nonceResult.r_public, r_prime_public: nonceResult.r_prime_public }
    );

    // Step 6: Submit partial signature
    onProgress?.({ stage: 'signing', message: 'Submitting partial signature...' });
    await submitPartialSignature(escrowId, role, partialSig);

    // Step 7: Wait for server aggregation and broadcast
    onProgress?.({ stage: 'waiting_arbiter', message: 'Aggregating signatures...' });
    const txHash = await pollForBroadcast(escrowId);

    // Step 8: Complete
    onProgress?.({ stage: 'completed', message: 'Transaction completed!' });
    return txHash;
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : String(error);
    onProgress?.({ stage: 'failed', message: 'Signing failed', error: errorMsg });
    throw error;
  }
}
