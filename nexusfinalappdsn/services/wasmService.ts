/**
 * WASM Service - Full Monero Multisig Signing via wallet_wasm
 *
 * This file wraps the wallet_wasm module which provides COMPLETE signing capability.
 * All cryptographic operations execute client-side in the browser.
 *
 * Exports:
 * - FROST DKG: frost_dkg_part1, frost_dkg_part2, frost_dkg_part3
 * - FROST Signing: frost_extract_secret_share, frost_derive_address
 * - CLSAG Signing: create_partial_tx_wasm, complete_partial_tx_wasm, verify_clsag_wasm
 * - Key Images: compute_partial_key_image, aggregate_key_images
 * - Nonces: generate_nonce_commitment, verify_nonce_commitment, aggregate_nonces
 * - Encryption: generate_keypair, encrypt_data, decrypt_data
 * - Backup: encrypt_key_for_backup, decrypt_key_from_backup, derive_backup_id
 * - Utilities: sha3_256, is_valid_hex, bytes_to_hex, hex_to_bytes, compute_lagrange_coefficient
 */

// Type definitions for WASM exports
export interface DkgPart1Result {
  round1_package: string;
  secret_package: string;
}

export interface DkgPart2Result {
  round2_packages: Record<string, string>;
  round2_secret: string;
}

export interface DkgPart3Result {
  key_package: string;
  public_key_package: string;
  group_public_key: string;
}

export interface OutputResult {
  output_index: number;
  commitment_mask: string;
  decoded_amount: number | null;
}

export interface PartialKeyImageResult {
  partial_key_image: string;
  one_time_pubkey: string;
  lagrange_applied: boolean;
}

// ============================================================================
// CLSAG Signing Types
// ============================================================================

export interface FrostDeriveAddressResult {
  address: string;
  view_key_private: string;
  view_key_public: string;
}

export interface ClsagSignature {
  D: string;           // D point (hex)
  s: string[];         // s values array (hex scalars)
  c1: string;          // c1 scalar (hex)
}

export interface SignClsagResult {
  signature: ClsagSignature;
  keyImage: string;
  pseudoOut: string;
}

export interface SignClsagPartialResult {
  signature: ClsagSignature;
  keyImage: string;
  partialKeyImage: string;
  pseudoOut: string;
}

export interface PartialTxData {
  encrypted_alpha: string;       // Alpha encrypted for Signer 2
  partial_s: string[];           // Partial s values
  c1: string;                    // Challenge scalar
  D: string;                     // D point
  key_image: string;             // Key image
  pseudo_out: string;            // Pseudo-output commitment
  ring: string[][];              // Ring members
  tx_prefix_hash: string;        // TX prefix hash
  signer_index: number;          // Real output index in ring
  mu_P: string;                  // MuSig2 aggregated nonce coefficient
  mu_C: string;                  // MuSig2 aggregated commitment coefficient
}

export interface CreatePartialTxResult {
  partial_tx: PartialTxData;
  alpha_encrypted: string;       // For relay to Signer 2
  signer1_pubkey: string;        // Signer 1's ephemeral pubkey for decryption
}

export interface CompletePartialTxResult {
  signature: ClsagSignature;
  key_image: string;
  pseudo_out: string;
  verified: boolean;             // Local verification passed
}

export interface VerifyClsagResult {
  valid: boolean;
  error?: string;
}

export interface NonceCommitmentResult {
  commitment_hash: string;
  r_public: string;
  r_prime_public: string;
  alpha_secret: string;
}

export interface KeypairResult {
  private_key_hex: string;
  public_key_hex: string;
}

export interface EncryptResult {
  encrypted_blob: string;
  nonce_hex: string;
  ephemeral_pubkey_hex: string;
}

// WASM module type
interface WasmModule {
  default: (wasmPath?: string | URL) => Promise<void>;

  // FROST DKG
  frost_dkg_part1: (participant_id: number, threshold: number, total_signers: number) => DkgPart1Result;
  frost_dkg_part2: (secret_package_hex: string, round1_packages_json: string) => DkgPart2Result;
  frost_dkg_part3: (round2_secret_hex: string, round1_packages_json: string, round2_packages_json: string) => DkgPart3Result;
  frost_extract_secret_share: (key_package_hex: string) => string;
  frost_compute_lagrange_coefficient: (signer_index: number, signer1_index: number, signer2_index: number) => string;
  frost_derive_address: (group_pubkey_hex: string, escrow_id: string, network?: string) => FrostDeriveAddressResult;
  frost_role_to_index: (role: string) => number;

  // CMD Protocol
  derive_commitment_mask: (view_key_priv_hex: string, tx_pub_key_hex: string, output_index: bigint) => string;
  find_our_output: (view_key_priv_hex: string, tx_pub_key_hex: string, multisig_address: string, output_keys_json: string) => OutputResult;

  // Key Images
  compute_partial_key_image: (spend_key_priv_hex: string, one_time_pubkey_hex: string, lagrange_coeff_hex: string) => PartialKeyImageResult;
  compute_partial_key_image_with_derivation: (
    spend_key_hex: string,
    tx_pub_key_hex: string,
    view_key_shared_hex: string,
    output_index: bigint,
    one_time_pubkey_hex: string,
    lagrange_coefficient_hex: string
  ) => { partialKeyImage: string; derivationScalar: string };
  aggregate_key_images: (pki1_hex: string, pki2_hex: string) => string;

  // Nonces (MuSig2-style)
  generate_nonce_commitment: (tx_prefix_hash: string, multisig_pub_key_hex: string) => NonceCommitmentResult;
  verify_nonce_commitment: (commitment_hash_hex: string, r_public_hex: string, r_prime_public_hex: string) => boolean;
  aggregate_nonces: (r1_hex: string, r2_hex: string) => string;

  // CLSAG Signing (FULL capability)
  sign_clsag_wasm: (
    spend_key_priv_hex: string,
    input_data_json: string,
    tx_prefix_hash_hex: string
  ) => SignClsagResult;

  sign_clsag_partial_wasm: (
    spend_key_priv_hex: string,
    input_data_json: string,
    tx_prefix_hash_hex: string,
    multisig_pub_key_hex: string,
    aggregated_key_image_hex: string,
    first_signer_c1_hex: string | null,
    first_signer_s_values_json: string | null,
    first_signer_d_hex: string | null,
    mu_p_hex: string | null,
    mu_c_hex: string | null,
    first_signer_pseudo_out_hex: string | null,
    first_signer_used_r_agg: boolean,
    lagrange_coefficient_hex: string
  ) => SignClsagPartialResult;

  create_partial_tx_wasm: (
    spend_key_priv_hex: string,
    mask_share_hex: string,
    signer2_public_hex: string,
    input_data_json: string,
    tx_prefix_hash_hex: string,
    key_image_hex: string,
    multisig_pub_key_hex: string
  ) => CreatePartialTxResult;

  create_partial_tx_wasm_with_derivation: (
    spend_key_priv_hex: string,
    mask_share_hex: string,
    signer2_public_hex: string,
    input_data_json: string,
    tx_prefix_hash_hex: string,
    key_image_hex: string,
    multisig_pub_key_hex: string,
    tx_pub_key_hex: string,
    view_key_hex: string,
    output_index: bigint
  ) => CreatePartialTxResult;

  complete_partial_tx_wasm: (
    spend_key_priv_hex: string,
    mask_share_hex: string,
    partial_tx_json: string
  ) => CompletePartialTxResult;

  verify_clsag_wasm: (
    signature_json: string,
    ring_json: string,
    tx_prefix_hash_hex: string
  ) => VerifyClsagResult;

  dump_clsag_params_wasm: (
    signature_json: string,
    ring_json: string,
    tx_prefix_hash_hex: string
  ) => unknown;

  // Wallet Generation
  generate_monero_wallet: () => {
    seed: string;
    address: string;
    viewKeyPub: string;
    spendKeyPub: string;
    viewKeyPriv: string;
    spendKeyPriv: string;
  };
  restore_wallet_from_seed: (seed_phrase: string) => {
    seed: string;
    address: string;
    viewKeyPub: string;
    spendKeyPub: string;
    viewKeyPriv: string;
    spendKeyPriv: string;
  };

  // Multisig Setup (legacy)
  prepare_multisig_wasm: (spend_key_priv_hex: string, view_key_priv_hex: string) => {
    multisigInfo: string;
    stage: string;
  };
  make_multisig_wasm: (
    spend_key_priv_hex: string,
    my_view_key_hex: string,
    peer_view_keys_json: string,
    peer_infos_json: string
  ) => {
    multisigAddress: string;
    sharedViewKey: string;
    stage: string;
    threshold: number;
    total: number;
  };

  // Encryption
  generate_ephemeral_keypair: () => KeypairResult;
  encrypt_partial_signature: (data_json: string, my_private_key_hex: string, peer_public_key_hex: string) => EncryptResult;
  decrypt_partial_signature: (encrypted_blob_base64: string, nonce_hex: string, peer_pubkey_hex: string, my_private_key_hex: string) => string;
  encrypt_key_for_backup: (key_package_hex: string, password: string) => string;
  decrypt_key_from_backup: (encrypted_hex: string, password: string) => string;
  derive_backup_id: (key_package_hex: string) => string;
  verify_backup_password: (encrypted_hex: string, password: string) => boolean;
  backup_encrypted_size: (plaintext_len: number) => number;

  // Utilities
  sha3_256: (data_hex: string) => string;
  is_valid_hex: (s: string) => boolean;
  bytes_to_hex: (bytes: Uint8Array) => string;
  hex_to_bytes: (hex_str: string) => Uint8Array;
  compute_lagrange_coefficient: (signer_index: number, signer1_index: number, signer2_index: number) => string;
  get_version: () => string;
  init_panic_hook: () => void;
}

// Module state
let wasmModule: WasmModule | null = null;
let initPromise: Promise<void> | null = null;

/**
 * Initialize the WASM module using fetch + blob URL
 *
 * This approach bypasses Vite's import analysis completely by:
 * 1. Fetching the JS wrapper as text
 * 2. Creating a blob URL
 * 3. Dynamically importing from the blob URL
 *
 * Must be called before using any WASM functions.
 * Safe to call multiple times - subsequent calls are no-ops.
 */
export async function initWasm(): Promise<void> {
  if (wasmModule !== null) {
    return;
  }

  if (initPromise !== null) {
    return initPromise;
  }

  initPromise = (async () => {
    try {
      // wallet_wasm provides FULL signing capability (DKG + CLSAG)
      const wasmJsUrl = '/wasm/wallet_wasm.js';
      const wasmBinaryUrl = '/wasm/wallet_wasm_bg.wasm';
      const absoluteWasmUrl = new URL(wasmBinaryUrl, window.location.origin).href;

      // Fetch the JS wrapper
      const jsResponse = await fetch(wasmJsUrl);
      if (!jsResponse.ok) {
        throw new Error(`Failed to fetch WASM JS: ${jsResponse.status}`);
      }
      let jsCode = await jsResponse.text();

      // Replace import.meta.url references with actual origin
      // The wasm-bindgen code uses: new URL("...", import.meta.url)
      jsCode = jsCode.replace(
        /import\.meta\.url/g,
        `"${window.location.origin}/wasm/"`
      );

      // Create blob URL and import
      const blob = new Blob([jsCode], { type: 'application/javascript' });
      const blobUrl = URL.createObjectURL(blob);

      try {
        const module = await import(/* @vite-ignore */ blobUrl) as WasmModule;

        // Initialize the WASM module with explicit WASM URL
        // This avoids import.meta.url issues in blob context
        await module.default(absoluteWasmUrl);

        wasmModule = module;
        console.log('[WASM] wallet_wasm loaded successfully (FULL signing capability)');
      } finally {
        // Clean up blob URL
        URL.revokeObjectURL(blobUrl);
      }
    } catch (error) {
      initPromise = null;
      console.error('[WASM] Failed to load wallet_wasm:', error);
      throw new Error(`WASM initialization failed: ${error instanceof Error ? error.message : String(error)}`);
    }
  })();

  return initPromise;
}

/**
 * Check if WASM module is initialized
 */
export function isWasmReady(): boolean {
  return wasmModule !== null;
}

/**
 * Get WASM module version
 */
export function getWasmVersion(): string {
  assertWasmReady();
  return wasmModule!.get_version();
}

// Internal helper to ensure WASM is loaded
function assertWasmReady(): void {
  if (wasmModule === null) {
    throw new Error('WASM not initialized. Call initWasm() first.');
  }
}

// ============================================================================
// FROST DKG Functions
// ============================================================================

/**
 * FROST DKG Round 1 - Generate initial key share data
 *
 * @param participantId - Unique identifier (1-3 for 2-of-3)
 * @param threshold - Required signers (2 for 2-of-3)
 * @param totalSigners - Total signers (3 for 2-of-3)
 * @returns Object containing round1_package and secret_package (hex)
 */
export function frostDkgPart1(
  participantId: number,
  threshold: number = 2,
  totalSigners: number = 3
): DkgPart1Result {
  assertWasmReady();
  return wasmModule!.frost_dkg_part1(participantId, threshold, totalSigners);
}

/**
 * FROST DKG Round 2 - Process round 1 packages
 *
 * @param secretPackageHex - Your secret from round 1
 * @param round1Packages - All round 1 packages: {"1": "hex...", "2": "hex...", "3": "hex..."}
 * @returns Object containing round2_packages and round2_secret
 */
export function frostDkgPart2(
  secretPackageHex: string,
  round1Packages: Record<string, string>
): DkgPart2Result {
  assertWasmReady();
  const round1PackagesJson = JSON.stringify(round1Packages);
  return wasmModule!.frost_dkg_part2(secretPackageHex, round1PackagesJson);
}

/**
 * FROST DKG Round 3 (Final) - Generate final key share
 *
 * @param round2SecretHex - Your secret from round 2
 * @param round1Packages - All round 1 packages
 * @param round2Packages - Round 2 packages received
 * @returns Object containing key_package, public_key_package, and group_public_key
 */
export function frostDkgPart3(
  round2SecretHex: string,
  round1Packages: Record<string, string>,
  round2Packages: Record<string, string>
): DkgPart3Result {
  assertWasmReady();
  const round1PackagesJson = JSON.stringify(round1Packages);
  const round2PackagesJson = JSON.stringify(round2Packages);
  return wasmModule!.frost_dkg_part3(round2SecretHex, round1PackagesJson, round2PackagesJson);
}

// ============================================================================
// FROST Key Extraction & Address Derivation
// ============================================================================

/**
 * Extract the raw secret share scalar from a FROST KeyPackage
 *
 * This is used after DKG completes to get the private key share for signing.
 * The secret share can be used with the CLSAG signing functions.
 *
 * @param keyPackageHex - The key_package from frost_dkg_part3
 * @returns The raw 32-byte secret share as hex
 */
export function frostExtractSecretShare(keyPackageHex: string): string {
  assertWasmReady();
  return wasmModule!.frost_extract_secret_share(keyPackageHex);
}

/**
 * Derive Monero address and shared view key from FROST group public key
 *
 * This generates the escrow deposit address. All participants derive the
 * same address and view key deterministically from the group pubkey.
 *
 * @param groupPubkeyHex - The group_public_key from frost_dkg_part3 (64 hex chars)
 * @param escrowId - The escrow identifier (used as domain separator)
 * @returns Address, private view key, and public view key
 */
export function frostDeriveAddress(
  groupPubkeyHex: string,
  escrowId: string,
  network: string = 'mainnet'
): FrostDeriveAddressResult {
  assertWasmReady();
  return wasmModule!.frost_derive_address(groupPubkeyHex, escrowId, network);
}

/**
 * Get participant index from role string
 *
 * @param role - 'buyer', 'vendor', or 'arbiter'
 * @returns 1, 2, or 3
 */
export function frostRoleToIndex(role: string): number {
  assertWasmReady();
  return wasmModule!.frost_role_to_index(role);
}

// ============================================================================
// CLSAG Signing Functions (FULL CAPABILITY)
// ============================================================================

/**
 * Sign a single input with CLSAG ring signature (SINGLE-SIGNER MODE)
 *
 * For single-signer wallets only. For 2-of-3 multisig, use signClsagPartial.
 *
 * @param spendKeyPrivHex - Full private spend key (64 hex chars)
 * @param inputData - Ring data from server (SignInputData structure)
 * @param txPrefixHashHex - Transaction prefix hash (64 hex chars)
 * @returns CLSAG signature, key image, and pseudo-output
 */
export function signClsag(
  spendKeyPrivHex: string,
  inputData: Record<string, unknown>,
  txPrefixHashHex: string
): SignClsagResult {
  assertWasmReady();
  const inputDataJson = JSON.stringify(inputData);
  return wasmModule!.sign_clsag_wasm(spendKeyPrivHex, inputDataJson, txPrefixHashHex);
}

/**
 * Sign with partial key for 2-of-3 multisig CLSAG
 *
 * Each signer holds only a partial key (from FROST DKG). The ring contains
 * the aggregated multisig public key.
 *
 * @param spendKeyPrivHex - Signer's PARTIAL private spend key (from frostExtractSecretShare)
 * @param inputData - Ring data from server
 * @param txPrefixHashHex - Transaction prefix hash
 * @param multisigPubKeyHex - The aggregated multisig public key
 * @param aggregatedKeyImageHex - Pre-computed aggregated key image
 * @param firstSignerData - Optional data from first signer (for second signer)
 * @param lagrangeCoefficientHex - Lagrange coefficient for this signer
 * @returns Partial signature components for aggregation
 */
export function signClsagPartial(
  spendKeyPrivHex: string,
  inputData: Record<string, unknown>,
  txPrefixHashHex: string,
  multisigPubKeyHex: string,
  aggregatedKeyImageHex: string,
  firstSignerData: {
    c1: string;
    sValues: string[];
    D: string;
    muP: string;
    muC: string;
    pseudoOut: string;
    usedRAgg: boolean;
  } | null,
  lagrangeCoefficientHex: string
): SignClsagPartialResult {
  assertWasmReady();
  const inputDataJson = JSON.stringify(inputData);

  return wasmModule!.sign_clsag_partial_wasm(
    spendKeyPrivHex,
    inputDataJson,
    txPrefixHashHex,
    multisigPubKeyHex,
    aggregatedKeyImageHex,
    firstSignerData?.c1 ?? null,
    firstSignerData ? JSON.stringify(firstSignerData.sValues) : null,
    firstSignerData?.D ?? null,
    firstSignerData?.muP ?? null,
    firstSignerData?.muC ?? null,
    firstSignerData?.pseudoOut ?? null,
    firstSignerData?.usedRAgg ?? false,
    lagrangeCoefficientHex
  );
}

/**
 * Create a partial transaction (Signer 1 in round-robin signing)
 *
 * This function:
 * 1. Generates a random nonce alpha
 * 2. Computes the CLSAG ring loop
 * 3. Creates partial s[signer_index] with Signer 1's contribution
 * 4. Encrypts alpha for Signer 2
 *
 * @param spendKeyPrivHex - Signer 1's private spend key share
 * @param maskShareHex - Signer 1's commitment mask share
 * @param signer2PublicHex - Signer 2's public key (for alpha encryption)
 * @param inputData - Ring data from server
 * @param txPrefixHashHex - Transaction prefix hash
 * @param keyImageHex - Pre-computed aggregated key image
 * @param multisigPubKeyHex - The multisig public key
 * @returns Partial transaction data to relay to Signer 2
 */
export function createPartialTx(
  spendKeyPrivHex: string,
  maskShareHex: string,
  signer2PublicHex: string,
  inputData: Record<string, unknown>,
  txPrefixHashHex: string,
  keyImageHex: string,
  multisigPubKeyHex: string
): CreatePartialTxResult {
  assertWasmReady();
  const inputDataJson = JSON.stringify(inputData);
  return wasmModule!.create_partial_tx_wasm(
    spendKeyPrivHex,
    maskShareHex,
    signer2PublicHex,
    inputDataJson,
    txPrefixHashHex,
    keyImageHex,
    multisigPubKeyHex
  );
}

/**
 * Create a partial transaction with derivation (Signer 1)
 *
 * Full version with output secret derivation:
 * x = H_s(a * R || output_index) + b
 *
 * @param spendKeyPrivHex - Signer 1's private spend key share
 * @param maskShareHex - Signer 1's commitment mask share
 * @param signer2PublicHex - Signer 2's public key
 * @param inputData - Ring data from server
 * @param txPrefixHashHex - Transaction prefix hash
 * @param keyImageHex - Pre-computed key image
 * @param multisigPubKeyHex - Multisig public key
 * @param txPubKeyHex - TX public key R from funding transaction
 * @param viewKeyHex - Shared view private key
 * @param outputIndex - Output index in the funding transaction
 * @returns Partial transaction data
 */
export function createPartialTxWithDerivation(
  spendKeyPrivHex: string,
  maskShareHex: string,
  signer2PublicHex: string,
  inputData: Record<string, unknown>,
  txPrefixHashHex: string,
  keyImageHex: string,
  multisigPubKeyHex: string,
  txPubKeyHex: string,
  viewKeyHex: string,
  outputIndex: number
): CreatePartialTxResult {
  assertWasmReady();
  const inputDataJson = JSON.stringify(inputData);
  return wasmModule!.create_partial_tx_wasm_with_derivation(
    spendKeyPrivHex,
    maskShareHex,
    signer2PublicHex,
    inputDataJson,
    txPrefixHashHex,
    keyImageHex,
    multisigPubKeyHex,
    txPubKeyHex,
    viewKeyHex,
    BigInt(outputIndex)
  );
}

/**
 * Complete a partial transaction (Signer 2 in round-robin signing)
 *
 * This function:
 * 1. Decrypts alpha from Signer 1
 * 2. Adds Signer 2's contribution to s[signer_index]
 * 3. Returns the completed CLSAG signature
 *
 * @param spendKeyPrivHex - Signer 2's private spend key share
 * @param maskShareHex - Signer 2's commitment mask share
 * @param partialTxData - Partial transaction from Signer 1
 * @returns Completed CLSAG signature ready for broadcast
 */
export function completePartialTx(
  spendKeyPrivHex: string,
  maskShareHex: string,
  partialTxData: PartialTxData
): CompletePartialTxResult {
  assertWasmReady();
  const partialTxJson = JSON.stringify(partialTxData);
  return wasmModule!.complete_partial_tx_wasm(spendKeyPrivHex, maskShareHex, partialTxJson);
}

/**
 * Verify a CLSAG signature locally before broadcast
 *
 * This performs the exact verification the Monero daemon will perform.
 * ALWAYS verify signatures before broadcasting!
 *
 * @param signature - The CLSAG signature to verify
 * @param ring - The ring members array
 * @param txPrefixHashHex - Transaction prefix hash
 * @returns Whether the signature is valid
 */
export function verifyClsag(
  signature: ClsagSignature,
  ring: string[][],
  txPrefixHashHex: string
): VerifyClsagResult {
  assertWasmReady();
  const signatureJson = JSON.stringify(signature);
  const ringJson = JSON.stringify(ring);
  return wasmModule!.verify_clsag_wasm(signatureJson, ringJson, txPrefixHashHex);
}

/**
 * Compute partial key image with output derivation
 *
 * For spending Monero one-time outputs in multisig:
 * pKI = (H_s(a*R || idx) + b) * Hp(P)
 *
 * @param spendKeyHex - Signer's private spend key share
 * @param txPubKeyHex - TX public key R from funding transaction
 * @param viewKeySharedHex - Shared multisig view key
 * @param outputIndex - Output index
 * @param oneTimePubkeyHex - The one-time output public key P
 * @param lagrangeCoefficientHex - Lagrange coefficient
 * @returns Partial key image and derivation scalar
 */
export function computePartialKeyImageWithDerivation(
  spendKeyHex: string,
  txPubKeyHex: string,
  viewKeySharedHex: string,
  outputIndex: number,
  oneTimePubkeyHex: string,
  lagrangeCoefficientHex: string
): { partialKeyImage: string; derivationScalar: string } {
  assertWasmReady();
  return wasmModule!.compute_partial_key_image_with_derivation(
    spendKeyHex,
    txPubKeyHex,
    viewKeySharedHex,
    BigInt(outputIndex),
    oneTimePubkeyHex,
    lagrangeCoefficientHex
  );
}

// ============================================================================
// Wallet Generation Functions
// ============================================================================

/**
 * Generate a new Monero wallet with spend/view keys
 *
 * SECURITY: Private keys returned ONCE for user backup.
 * Caller must store securely (encrypted IndexedDB).
 */
export function generateMoneroWallet(): {
  seed: string;
  address: string;
  viewKeyPub: string;
  spendKeyPub: string;
  viewKeyPriv: string;
  spendKeyPriv: string;
} {
  assertWasmReady();
  return wasmModule!.generate_monero_wallet();
}

/**
 * Restore wallet from BIP39 seed phrase
 *
 * @param seedPhrase - 12-word BIP39 mnemonic
 */
export function restoreWalletFromSeed(seedPhrase: string): {
  seed: string;
  address: string;
  viewKeyPub: string;
  spendKeyPub: string;
  viewKeyPriv: string;
  spendKeyPriv: string;
} {
  assertWasmReady();
  return wasmModule!.restore_wallet_from_seed(seedPhrase);
}

// ============================================================================
// CMD Protocol Functions
// ============================================================================

/**
 * Derive commitment mask from view key and transaction public key
 */
export function deriveCommitmentMask(
  viewKeyPrivHex: string,
  txPubKeyHex: string,
  outputIndex: number
): string {
  assertWasmReady();
  return wasmModule!.derive_commitment_mask(viewKeyPrivHex, txPubKeyHex, BigInt(outputIndex));
}

/**
 * Find our output in a transaction and derive commitment mask
 */
export function findOurOutput(
  viewKeyPrivHex: string,
  txPubKeyHex: string,
  multisigAddress: string,
  outputKeys: string[]
): OutputResult {
  assertWasmReady();
  const outputKeysJson = JSON.stringify(outputKeys);
  return wasmModule!.find_our_output(viewKeyPrivHex, txPubKeyHex, multisigAddress, outputKeysJson);
}

// ============================================================================
// Key Image Functions
// ============================================================================

/**
 * Compute partial key image for threshold signing
 */
export function computePartialKeyImage(
  spendKeyPrivHex: string,
  oneTimePubkeyHex: string,
  lagrangeCoeffHex: string
): PartialKeyImageResult {
  assertWasmReady();
  return wasmModule!.compute_partial_key_image(spendKeyPrivHex, oneTimePubkeyHex, lagrangeCoeffHex);
}

/**
 * Aggregate two partial key images into final key image
 */
export function aggregateKeyImages(pki1Hex: string, pki2Hex: string): string {
  assertWasmReady();
  return wasmModule!.aggregate_key_images(pki1Hex, pki2Hex);
}

// ============================================================================
// Nonce Commitment Functions
// ============================================================================

/**
 * Generate nonce commitment for signing (MuSig2-style)
 *
 * @param txPrefixHash - The transaction prefix hash (or CLSAG message)
 * @param multisigPubKeyHex - The multisig public key
 */
export function generateNonceCommitment(
  txPrefixHash: string,
  multisigPubKeyHex: string
): NonceCommitmentResult {
  assertWasmReady();
  return wasmModule!.generate_nonce_commitment(txPrefixHash, multisigPubKeyHex);
}

/**
 * Verify a nonce commitment
 */
export function verifyNonceCommitment(
  commitmentHashHex: string,
  rPublicHex: string,
  rPrimePublicHex: string
): boolean {
  assertWasmReady();
  return wasmModule!.verify_nonce_commitment(commitmentHashHex, rPublicHex, rPrimePublicHex);
}

/**
 * Aggregate two nonces (for 2-of-3 signing)
 */
export function aggregateNonces(r1Hex: string, r2Hex: string): string {
  assertWasmReady();
  return wasmModule!.aggregate_nonces(r1Hex, r2Hex);
}

// ============================================================================
// Encryption Functions (X25519 + ChaCha20Poly1305)
// ============================================================================

/**
 * Generate X25519 keypair for encryption
 */
export function generateKeypair(): KeypairResult {
  assertWasmReady();
  return wasmModule!.generate_ephemeral_keypair();
}

/**
 * Encrypt data using X25519 ECDH + ChaCha20Poly1305
 */
export function encryptData(
  plaintext: string,
  myPrivateKeyHex: string,
  peerPublicKeyHex: string
): EncryptResult {
  assertWasmReady();
  return wasmModule!.encrypt_partial_signature(plaintext, myPrivateKeyHex, peerPublicKeyHex);
}

/**
 * Decrypt data using X25519 ECDH + ChaCha20Poly1305
 */
export function decryptData(
  encryptedBlobBase64: string,
  nonceHex: string,
  peerPublicKeyHex: string,
  myPrivateKeyHex: string
): string {
  assertWasmReady();
  return wasmModule!.decrypt_partial_signature(encryptedBlobBase64, nonceHex, peerPublicKeyHex, myPrivateKeyHex);
}

// ============================================================================
// Key Backup Encryption Functions (PBKDF2 + AES-GCM via Web Crypto API)
// ============================================================================

// Constants for encryption
const PBKDF2_ITERATIONS = 100000;
const SALT_LENGTH = 16;
const IV_LENGTH = 12;
const KEY_LENGTH = 256;

/**
 * Helper: Convert hex string to Uint8Array
 */
function hexToUint8Array(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}

/**
 * Helper: Convert Uint8Array to hex string
 */
function uint8ArrayToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Derive encryption key from password using PBKDF2
 */
async function deriveKeyFromPassword(
  password: string,
  salt: Uint8Array
): Promise<CryptoKey> {
  const encoder = new TextEncoder();
  const passwordData = encoder.encode(password);

  const baseKey = await crypto.subtle.importKey(
    'raw',
    passwordData,
    'PBKDF2',
    false,
    ['deriveKey']
  );

  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt,
      iterations: PBKDF2_ITERATIONS,
      hash: 'SHA-256',
    },
    baseKey,
    { name: 'AES-GCM', length: KEY_LENGTH },
    false,
    ['encrypt', 'decrypt']
  );
}

/**
 * Encrypt a FROST key_package for secure backup
 *
 * Uses PBKDF2 for password-based key derivation and AES-GCM for authenticated encryption.
 * Format: salt (16 bytes) || iv (12 bytes) || ciphertext || tag (included in ciphertext)
 */
export async function encryptKeyForBackupAsync(
  keyPackageHex: string,
  password: string
): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));

  const key = await deriveKeyFromPassword(password, salt);
  const plaintext = hexToUint8Array(keyPackageHex);

  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    plaintext
  );

  // Combine: salt + iv + ciphertext
  const result = new Uint8Array(
    salt.length + iv.length + ciphertext.byteLength
  );
  result.set(salt, 0);
  result.set(iv, salt.length);
  result.set(new Uint8Array(ciphertext), salt.length + iv.length);

  return uint8ArrayToHex(result);
}

/**
 * Decrypt a FROST key_package from backup
 */
export async function decryptKeyFromBackupAsync(
  encryptedHex: string,
  password: string
): Promise<string> {
  const encrypted = hexToUint8Array(encryptedHex);

  const salt = encrypted.slice(0, SALT_LENGTH);
  const iv = encrypted.slice(SALT_LENGTH, SALT_LENGTH + IV_LENGTH);
  const ciphertext = encrypted.slice(SALT_LENGTH + IV_LENGTH);

  const key = await deriveKeyFromPassword(password, salt);

  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    key,
    ciphertext
  );

  return uint8ArrayToHex(new Uint8Array(plaintext));
}

/**
 * Derive a backup identifier from key_package (without exposing the key)
 *
 * Uses SHA-256 with domain separation for deterministic ID generation.
 */
export async function deriveBackupIdAsync(keyPackageHex: string): Promise<string> {
  const encoder = new TextEncoder();
  const domain = encoder.encode('nexus:backup:id:');
  const keyData = hexToUint8Array(keyPackageHex);

  const combined = new Uint8Array(domain.length + keyData.length);
  combined.set(domain, 0);
  combined.set(keyData, domain.length);

  const hash = await crypto.subtle.digest('SHA-256', combined);
  return uint8ArrayToHex(new Uint8Array(hash)).slice(0, 32);
}

/**
 * Verify that a password can decrypt a backup without returning the key
 */
export async function verifyBackupPasswordAsync(
  encryptedHex: string,
  password: string
): Promise<boolean> {
  try {
    await decryptKeyFromBackupAsync(encryptedHex, password);
    return true;
  } catch {
    return false;
  }
}

// Synchronous wrappers that throw if called before async completion
// These are used for compatibility with the existing API

let _encryptCache: Map<string, string> = new Map();
let _decryptCache: Map<string, string> = new Map();

/**
 * Encrypt a FROST key_package for secure backup (sync wrapper)
 * Note: Actually performs async operation and caches result
 */
export function encryptKeyForBackup(keyPackageHex: string, password: string): string {
  // Start async operation and return placeholder
  const cacheKey = `${keyPackageHex}:${password}`;

  // Check cache first
  if (_encryptCache.has(cacheKey)) {
    return _encryptCache.get(cacheKey)!;
  }

  // Perform synchronously using a blocking approach (not ideal but compatible)
  // In practice, the caller should use the async version
  throw new Error('Use encryptKeyForBackupAsync() instead for async encryption');
}

/**
 * Decrypt a FROST key_package from backup (sync wrapper)
 */
export function decryptKeyFromBackup(encryptedHex: string, password: string): string {
  throw new Error('Use decryptKeyFromBackupAsync() instead for async decryption');
}

/**
 * Derive a backup identifier from key_package
 */
export function deriveBackupId(keyPackageHex: string): string {
  // Use a simple sync hash for backup ID (doesn't need crypto strength)
  let hash = 0;
  const str = 'nexus:backup:' + keyPackageHex;
  for (let i = 0; i < str.length; i++) {
    const char = str.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash; // Convert to 32bit integer
  }
  return Math.abs(hash).toString(16).padStart(8, '0') +
         keyPackageHex.slice(0, 24);
}

/**
 * Verify that a password can decrypt a backup
 */
export function verifyBackupPassword(encryptedHex: string, password: string): boolean {
  throw new Error('Use verifyBackupPasswordAsync() instead');
}

/**
 * Get the expected encrypted size for a given plaintext size
 */
export function backupEncryptedSize(plaintextLen: number): number {
  // salt (16) + iv (12) + ciphertext (plaintextLen) + tag (16)
  return SALT_LENGTH + IV_LENGTH + plaintextLen + 16;
}

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Compute SHA3-256 hash
 */
export function sha3_256(dataHex: string): string {
  assertWasmReady();
  return wasmModule!.sha3_256(dataHex);
}

/**
 * Validate hex string format
 */
export function isValidHex(s: string): boolean {
  assertWasmReady();
  return wasmModule!.is_valid_hex(s);
}

/**
 * Convert bytes to hex string
 */
export function bytesToHex(bytes: Uint8Array): string {
  assertWasmReady();
  return wasmModule!.bytes_to_hex(bytes);
}

/**
 * Convert hex string to bytes
 */
export function hexToBytes(hexStr: string): Uint8Array {
  assertWasmReady();
  return wasmModule!.hex_to_bytes(hexStr);
}

/**
 * Compute Lagrange coefficient for participant in 2-of-3 signing
 *
 * @param signerIndex - This signer's index (1, 2, or 3)
 * @param signer1Index - First participating signer's index
 * @param signer2Index - Second participating signer's index
 * @returns Lagrange coefficient as hex string (32 bytes scalar)
 */
export function computeLagrangeCoefficient(
  signerIndex: number,
  signer1Index: number,
  signer2Index: number
): string {
  assertWasmReady();
  return wasmModule!.compute_lagrange_coefficient(signerIndex, signer1Index, signer2Index);
}

// ============================================================================
// Role-to-Index Mapping (for FROST)
// ============================================================================

export const FROST_PARTICIPANT_INDEX: Record<string, number> = {
  buyer: 1,
  vendor: 2,
  arbiter: 3,
};

export function roleToParticipantIndex(role: string): number {
  const index = FROST_PARTICIPANT_INDEX[role.toLowerCase()];
  if (index === undefined) {
    throw new Error(`Invalid role: ${role}. Must be 'buyer', 'vendor', or 'arbiter'.`);
  }
  return index;
}

export function participantIndexToRole(index: number): string {
  const roles = ['buyer', 'vendor', 'arbiter'];
  if (index < 1 || index > 3) {
    throw new Error(`Invalid participant index: ${index}. Must be 1, 2, or 3.`);
  }
  return roles[index - 1];
}

// ============================================================================
// Group Encryption Functions (for E2EE Messaging)
// ============================================================================

export interface X25519Keypair {
  publicKey: string;
  privateKey: string;
}

export interface GroupEncryptResult {
  ciphertexts: string[];
  ephemeralPubkey: string;
  nonce: string;
}

/**
 * Generate X25519 keypair for messaging
 * Returns { publicKey, privateKey } format for chat use
 */
export function generate_x25519_keypair(): X25519Keypair {
  assertWasmReady();
  const result = wasmModule!.generate_ephemeral_keypair();
  return {
    publicKey: result.public_key_hex,
    privateKey: result.private_key_hex,
  };
}

/**
 * Encrypt a message for multiple recipients (group chat)
 *
 * Creates individual ciphertext for each recipient using ephemeral key exchange.
 * Same nonce is safe because each recipient gets a different shared secret.
 *
 * @param plaintext - Message to encrypt
 * @param recipientPubkeys - Array of recipient public keys (hex)
 * @param senderPrivateKey - Sender's private key (hex)
 * @returns Object with ciphertexts array, ephemeral pubkey, and nonce
 */
export function encrypt_for_group(
  plaintext: string,
  recipientPubkeys: string[],
  senderPrivateKey: string
): GroupEncryptResult {
  assertWasmReady();

  // Generate ephemeral keypair for this message
  const ephemeral = wasmModule!.generate_ephemeral_keypair();

  // Encrypt for each recipient using ephemeral private key
  const ciphertexts: string[] = [];
  let sharedNonce: string = '';

  for (const recipientPubkey of recipientPubkeys) {
    const encrypted = wasmModule!.encrypt_partial_signature(
      plaintext,
      ephemeral.private_key_hex,
      recipientPubkey
    );
    ciphertexts.push(encrypted.encrypted_blob);

    // All encryptions use same nonce (safe: different keys)
    if (!sharedNonce) {
      sharedNonce = encrypted.nonce_hex;
    }
  }

  return {
    ciphertexts,
    ephemeralPubkey: ephemeral.public_key_hex,
    nonce: sharedNonce,
  };
}

/**
 * Decrypt a group message
 *
 * @param encryptedContent - The ciphertext for this recipient
 * @param senderEphemeralPubkey - Sender's ephemeral public key
 * @param nonce - Encryption nonce
 * @param recipientPrivateKey - Recipient's private key
 * @returns Decrypted plaintext
 */
export function decrypt_group_message(
  encryptedContent: string,
  senderEphemeralPubkey: string,
  nonce: string,
  recipientPrivateKey: string
): string {
  assertWasmReady();
  return wasmModule!.decrypt_partial_signature(
    encryptedContent,
    nonce,
    senderEphemeralPubkey,
    recipientPrivateKey
  );
}

// ============================================================================
// Getters for Module Access (for hooks that need raw module)
// ============================================================================

/**
 * Get the WASM module with all exported functions
 * Used by hooks that need direct WASM access
 */
export function getWasmModule(): WasmModuleWrapper | null {
  if (!wasmModule) return null;

  // Return a wrapper that exposes both direct and convenience APIs
  return {
    // FROST DKG (direct exports)
    frost_dkg_part1: wasmModule.frost_dkg_part1,
    frost_dkg_part2: wasmModule.frost_dkg_part2,
    frost_dkg_part3: wasmModule.frost_dkg_part3,
    frost_extract_secret_share: wasmModule.frost_extract_secret_share,
    frost_derive_address: wasmModule.frost_derive_address,
    frost_role_to_index: wasmModule.frost_role_to_index,
    frost_compute_lagrange_coefficient: wasmModule.frost_compute_lagrange_coefficient,

    // CLSAG Signing (direct exports)
    sign_clsag_wasm: wasmModule.sign_clsag_wasm,
    sign_clsag_partial_wasm: wasmModule.sign_clsag_partial_wasm,
    create_partial_tx_wasm: wasmModule.create_partial_tx_wasm,
    create_partial_tx_wasm_with_derivation: wasmModule.create_partial_tx_wasm_with_derivation,
    complete_partial_tx_wasm: wasmModule.complete_partial_tx_wasm,
    verify_clsag_wasm: wasmModule.verify_clsag_wasm,

    // CMD Protocol
    derive_commitment_mask: wasmModule.derive_commitment_mask,
    find_our_output: wasmModule.find_our_output,

    // Key Images
    compute_partial_key_image: wasmModule.compute_partial_key_image,
    compute_partial_key_image_with_derivation: wasmModule.compute_partial_key_image_with_derivation,
    aggregate_key_images: wasmModule.aggregate_key_images,

    // Nonces
    generate_nonce_commitment: wasmModule.generate_nonce_commitment,
    verify_nonce_commitment: wasmModule.verify_nonce_commitment,
    aggregate_nonces: wasmModule.aggregate_nonces,

    // Wallet Generation
    generate_monero_wallet: wasmModule.generate_monero_wallet,
    restore_wallet_from_seed: wasmModule.restore_wallet_from_seed,

    // Encryption
    generate_ephemeral_keypair: wasmModule.generate_ephemeral_keypair,
    encrypt_partial_signature: wasmModule.encrypt_partial_signature,
    decrypt_partial_signature: wasmModule.decrypt_partial_signature,

    // Backup (with Uint8Array interface for hooks)
    // Note: These use simple XOR encryption since WASM backup functions aren't available
    encrypt_key_for_backup: (keyPackage: Uint8Array, password: string) => {
      // Simple XOR-based encryption (for Shield file - password-derived)
      const encoder = new TextEncoder();
      const passBytes = encoder.encode(password);
      const result = new Uint8Array(keyPackage.length);
      for (let i = 0; i < keyPackage.length; i++) {
        result[i] = keyPackage[i] ^ passBytes[i % passBytes.length];
      }
      return result;
    },
    decrypt_key_from_backup: (encryptedPayload: Uint8Array, password: string) => {
      // XOR decryption (symmetric)
      const encoder = new TextEncoder();
      const passBytes = encoder.encode(password);
      const result = new Uint8Array(encryptedPayload.length);
      for (let i = 0; i < encryptedPayload.length; i++) {
        result[i] = encryptedPayload[i] ^ passBytes[i % passBytes.length];
      }
      return result;
    },
    derive_backup_id: (escrowId: string, role: string) => {
      // Derive a deterministic 64-char hex backup ID (backend expects 64 hex chars)
      // Using FNV-1a hash run multiple times with different salts to generate 256 bits
      const fnv1a = (str: string): number => {
        let hash = 0x811c9dc5;
        for (let i = 0; i < str.length; i++) {
          hash ^= str.charCodeAt(i);
          hash = Math.imul(hash, 0x01000193);
        }
        return hash >>> 0;
      };

      const combined = `nexus:shield:${escrowId}:${role}`;
      // Generate 8 x 32-bit hashes = 256 bits = 64 hex chars
      const h1 = fnv1a(combined + ':1');
      const h2 = fnv1a(combined + ':2');
      const h3 = fnv1a(combined + ':3');
      const h4 = fnv1a(combined + ':4');
      const h5 = fnv1a(combined + ':5');
      const h6 = fnv1a(combined + ':6');
      const h7 = fnv1a(combined + ':7');
      const h8 = fnv1a(combined + ':8');

      return [h1, h2, h3, h4, h5, h6, h7, h8]
        .map(h => h.toString(16).padStart(8, '0'))
        .join('');
    },
    verify_backup_password: wasmModule.verify_backup_password,

    // Utilities
    sha3_256: wasmModule.sha3_256,
    is_valid_hex: wasmModule.is_valid_hex,
    bytes_to_hex: wasmModule.bytes_to_hex,
    hex_to_bytes: wasmModule.hex_to_bytes,
    compute_lagrange_coefficient: wasmModule.compute_lagrange_coefficient,
    get_version: wasmModule.get_version,

    // TypeScript Convenience APIs (typed wrappers)
    generate_x25519_keypair,
    encrypt_for_group,
    decrypt_group_message,
    frostExtractSecretShare,
    frostDeriveAddress,
    signClsag,
    signClsagPartial,
    createPartialTx,
    createPartialTxWithDerivation,
    completePartialTx,
    verifyClsag,
  };
}

// Type for the wrapper returned by getWasmModule
export interface WasmModuleWrapper {
  // FROST DKG
  frost_dkg_part1: WasmModule['frost_dkg_part1'];
  frost_dkg_part2: WasmModule['frost_dkg_part2'];
  frost_dkg_part3: WasmModule['frost_dkg_part3'];
  frost_extract_secret_share: WasmModule['frost_extract_secret_share'];
  frost_derive_address: WasmModule['frost_derive_address'];
  frost_role_to_index: WasmModule['frost_role_to_index'];
  frost_compute_lagrange_coefficient: WasmModule['frost_compute_lagrange_coefficient'];

  // CLSAG Signing (FULL capability)
  sign_clsag_wasm: WasmModule['sign_clsag_wasm'];
  sign_clsag_partial_wasm: WasmModule['sign_clsag_partial_wasm'];
  create_partial_tx_wasm: WasmModule['create_partial_tx_wasm'];
  create_partial_tx_wasm_with_derivation: WasmModule['create_partial_tx_wasm_with_derivation'];
  complete_partial_tx_wasm: WasmModule['complete_partial_tx_wasm'];
  verify_clsag_wasm: WasmModule['verify_clsag_wasm'];

  // CMD Protocol
  derive_commitment_mask: WasmModule['derive_commitment_mask'];
  find_our_output: WasmModule['find_our_output'];

  // Key Images
  compute_partial_key_image: WasmModule['compute_partial_key_image'];
  compute_partial_key_image_with_derivation: WasmModule['compute_partial_key_image_with_derivation'];
  aggregate_key_images: WasmModule['aggregate_key_images'];

  // Nonces
  generate_nonce_commitment: WasmModule['generate_nonce_commitment'];
  verify_nonce_commitment: WasmModule['verify_nonce_commitment'];
  aggregate_nonces: WasmModule['aggregate_nonces'];

  // Wallet Generation
  generate_monero_wallet: WasmModule['generate_monero_wallet'];
  restore_wallet_from_seed: WasmModule['restore_wallet_from_seed'];

  // Base Encryption
  generate_ephemeral_keypair: WasmModule['generate_ephemeral_keypair'];
  encrypt_partial_signature: WasmModule['encrypt_partial_signature'];
  decrypt_partial_signature: WasmModule['decrypt_partial_signature'];

  // Backup (with Uint8Array interface for hooks)
  encrypt_key_for_backup: (keyPackage: Uint8Array, password: string) => Uint8Array;
  decrypt_key_from_backup: (encryptedPayload: Uint8Array, password: string) => Uint8Array;
  derive_backup_id: (escrowId: string, role: string) => string;
  verify_backup_password: WasmModule['verify_backup_password'];

  // Utilities
  sha3_256: WasmModule['sha3_256'];
  is_valid_hex: WasmModule['is_valid_hex'];
  bytes_to_hex: WasmModule['bytes_to_hex'];
  hex_to_bytes: WasmModule['hex_to_bytes'];
  compute_lagrange_coefficient: WasmModule['compute_lagrange_coefficient'];
  get_version: WasmModule['get_version'];

  // Convenience APIs (TypeScript wrappers)
  generate_x25519_keypair: typeof generate_x25519_keypair;
  encrypt_for_group: typeof encrypt_for_group;
  decrypt_group_message: typeof decrypt_group_message;
  frostExtractSecretShare: typeof frostExtractSecretShare;
  frostDeriveAddress: typeof frostDeriveAddress;
  signClsag: typeof signClsag;
  signClsagPartial: typeof signClsagPartial;
  createPartialTx: typeof createPartialTx;
  createPartialTxWithDerivation: typeof createPartialTxWithDerivation;
  completePartialTx: typeof completePartialTx;
  verifyClsag: typeof verifyClsag;
}
