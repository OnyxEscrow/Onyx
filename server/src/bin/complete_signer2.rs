//! CLI tool to complete Signer 2's signature and submit to server
//! Usage: cargo run --bin complete_signer2 -- --escrow-id <id> --spend-key <hex>

use anyhow::{Context, Result};
use curve25519_dalek::{edwards::CompressedEdwardsY, scalar::Scalar};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sha3::Keccak256;

#[derive(Debug, Deserialize)]
struct PartialTx {
    ring_size: u32,
    signer_index: u32,
    s_values: Vec<String>,
    c1: String,
    d: String,
    pseudo_out: String,
    key_image: String,
    partial_key_image_1: Option<String>,
    alpha_encrypted: String,
    signer1_public: String,
    c_p: String,
    c_c: String,
    mask_delta: String,
    tx_prefix_hash: String,
    multisig_pub_key: Option<String>,
}

#[derive(Debug, Serialize)]
struct CompletedClsag {
    s_values: Vec<String>,
    c1: String,
    d: String,
    pseudo_out: String,
    key_image: String,
}

fn parse_hex_32(hex_str: &str, field: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(hex_str)
        .with_context(|| format!("Invalid hex for {}", field))?;
    if bytes.len() != 32 {
        anyhow::bail!("{} must be 32 bytes, got {}", field, bytes.len());
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

fn decrypt_scalar(encrypted: &[u8], key: &[u8; 32]) -> Result<Scalar> {
    // Expected format: 32-byte encrypted scalar + 8-byte MAC
    if encrypted.len() < 40 {
        anyhow::bail!("Encrypted data too short: {} bytes", encrypted.len());
    }

    let encrypted_scalar = &encrypted[..32];
    let mac = &encrypted[32..40];

    // Derive decryption key and MAC key
    let mut hasher = Sha256::new();
    hasher.update(b"NEXUS_ENCRYPT_V1");
    hasher.update(key);
    let derived: [u8; 32] = hasher.finalize().into();

    let dec_key = &derived[..16];
    let mac_key = &derived[16..32];

    // Verify MAC
    let mut mac_hasher = Sha256::new();
    mac_hasher.update(mac_key);
    mac_hasher.update(encrypted_scalar);
    let computed_mac: [u8; 32] = mac_hasher.finalize().into();

    if mac != &computed_mac[..8] {
        anyhow::bail!("MAC verification failed");
    }

    // XOR decrypt
    let mut decrypted = [0u8; 32];
    for i in 0..32 {
        decrypted[i] = encrypted_scalar[i] ^ dec_key[i % 16];
    }

    Ok(Scalar::from_bytes_mod_order(decrypted))
}

fn complete_signature(partial_tx: &PartialTx, spend_key_hex: &str, mask_share_hex: &str) -> Result<CompletedClsag> {
    println!("[Signer2] Starting signature completion...");

    // Parse Signer 2's keys
    let spend_key_arr = parse_hex_32(spend_key_hex, "spend_key")?;
    let x2 = Scalar::from_bytes_mod_order(spend_key_arr);

    let mask_arr = parse_hex_32(mask_share_hex, "mask_share")?;
    let _z2 = Scalar::from_bytes_mod_order(mask_arr);

    // Parse values from partial TX
    let c_p = Scalar::from_bytes_mod_order(parse_hex_32(&partial_tx.c_p, "c_p")?);
    let c_c = Scalar::from_bytes_mod_order(parse_hex_32(&partial_tx.c_c, "c_c")?);
    let mask_delta = Scalar::from_bytes_mod_order(parse_hex_32(&partial_tx.mask_delta, "mask_delta")?);

    // Get the aggregated key image
    let aggregated_key_image_bytes = parse_hex_32(&partial_tx.key_image, "key_image")?;
    println!("[Signer2] Using key image: {}", hex::encode(aggregated_key_image_bytes));

    // Decrypt alpha
    let tx_prefix_hash_arr = parse_hex_32(&partial_tx.tx_prefix_hash, "tx_prefix_hash")?;
    let key_image_arr = parse_hex_32(&partial_tx.key_image, "key_image")?;

    let shared_secret = {
        let mut hasher = Sha256::new();
        hasher.update(b"NEXUS_ROUND_ROBIN_SHARED_SECRET_V1");
        hasher.update(&tx_prefix_hash_arr);
        hasher.update(&key_image_arr);
        let result = hasher.finalize();
        let mut key = [0u8; 32];
        key.copy_from_slice(&result);
        key
    };

    let alpha_encrypted = hex::decode(&partial_tx.alpha_encrypted)
        .context("Invalid alpha_encrypted hex")?;
    let _alpha = decrypt_scalar(&alpha_encrypted, &shared_secret)?;
    println!("[Signer2] Alpha decrypted successfully");

    // Parse s values
    let mut s_values: Vec<Scalar> = partial_tx.s_values.iter()
        .map(|s_hex| {
            let bytes = hex::decode(s_hex).expect("valid hex");
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            Scalar::from_bytes_mod_order(arr)
        })
        .collect();

    let signer_idx = partial_tx.signer_index as usize;

    // Signer 2's contribution: -c_p * x2 - c_c * mask_delta
    let s2_contribution = -(c_p * x2) - (c_c * mask_delta);
    s_values[signer_idx] = s_values[signer_idx] + s2_contribution;

    println!("[Signer2] Signature completed. s[{}] finalized.", signer_idx);

    // Build completed signature
    Ok(CompletedClsag {
        s_values: s_values.iter().map(|s| hex::encode(s.to_bytes())).collect(),
        c1: partial_tx.c1.clone(),
        d: partial_tx.d.clone(),
        pseudo_out: partial_tx.pseudo_out.clone(),
        key_image: hex::encode(aggregated_key_image_bytes),
    })
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 5 {
        eprintln!("Usage: {} --escrow-id <id> --spend-key <hex> [--mask-share <hex>]", args[0]);
        eprintln!();
        eprintln!("This tool completes Signer 2's signature and updates the database directly.");
        std::process::exit(1);
    }

    let mut escrow_id = String::new();
    let mut spend_key = String::new();
    let mut mask_share = String::new();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--escrow-id" => {
                escrow_id = args.get(i + 1).cloned().unwrap_or_default();
                i += 2;
            }
            "--spend-key" => {
                spend_key = args.get(i + 1).cloned().unwrap_or_default();
                i += 2;
            }
            "--mask-share" => {
                mask_share = args.get(i + 1).cloned().unwrap_or_default();
                i += 2;
            }
            _ => i += 1,
        }
    }

    if escrow_id.is_empty() || spend_key.is_empty() {
        anyhow::bail!("--escrow-id and --spend-key are required");
    }

    // Use a dummy mask if not provided (for testing)
    if mask_share.is_empty() {
        mask_share = "0000000000000000000000000000000000000000000000000000000000000001".to_string();
    }

    println!("=== Signer 2 Completion Tool ===");
    println!("Escrow ID: {}", escrow_id);

    // Read partial_tx from database
    let db_key = std::env::var("DB_ENCRYPTION_KEY")
        .context("DB_ENCRYPTION_KEY not set")?;

    // Use sqlcipher to read partial_tx
    let output = std::process::Command::new("sqlcipher")
        .arg("marketplace.db")
        .arg(format!("PRAGMA key='{}'; SELECT partial_tx FROM escrows WHERE id='{}';", db_key, escrow_id))
        .output()
        .context("Failed to run sqlcipher")?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let lines: Vec<&str> = stdout.lines().collect();

    if lines.len() < 2 || lines[1].is_empty() {
        anyhow::bail!("No partial_tx found for escrow {}", escrow_id);
    }

    let partial_tx_json = lines[1];
    println!("[Signer2] Got partial_tx from DB ({} chars)", partial_tx_json.len());

    let partial_tx: PartialTx = serde_json::from_str(partial_tx_json)
        .context("Failed to parse partial_tx JSON")?;

    // Complete the signature
    let completed = complete_signature(&partial_tx, &spend_key, &mask_share)?;

    let completed_json = serde_json::to_string(&completed)?;
    println!("[Signer2] Completed CLSAG: {}", &completed_json[..100.min(completed_json.len())]);

    // Update database with completed signature
    let escaped_json = completed_json.replace("'", "''");
    let update_sql = format!(
        "PRAGMA key='{}'; UPDATE escrows SET completed_clsag='{}', signing_phase='completed', status='ready_to_broadcast', updated_at=datetime('now') WHERE id='{}';",
        db_key, escaped_json, escrow_id
    );

    let update_output = std::process::Command::new("sqlcipher")
        .arg("marketplace.db")
        .arg(&update_sql)
        .output()
        .context("Failed to update database")?;

    if !update_output.status.success() {
        anyhow::bail!("Database update failed: {}", String::from_utf8_lossy(&update_output.stderr));
    }

    println!("[Signer2] ✓ Database updated successfully!");
    println!("[Signer2] Status: ready_to_broadcast");
    println!("[Signer2] signing_phase: completed");

    // Verify the update
    let verify_output = std::process::Command::new("sqlcipher")
        .arg("marketplace.db")
        .arg(format!("PRAGMA key='{}'; SELECT status, signing_phase, length(completed_clsag) FROM escrows WHERE id='{}';", db_key, escrow_id))
        .output()?;

    println!("[Signer2] Verification: {}", String::from_utf8_lossy(&verify_output.stdout));

    Ok(())
}
