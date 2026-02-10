//! Utility to read escrow data from encrypted database
use anyhow::{Context, Result};
use diesel::prelude::*;
use diesel::r2d2::{self, ConnectionManager, CustomizeConnection};
use diesel::sql_query;
use std::env;

diesel::table! {
    escrows (id) {
        id -> Text,
        multisig_address -> Nullable<Text>,
        multisig_view_key -> Nullable<Text>,
        funding_tx_hash -> Nullable<Text>,
        funding_output_index -> Nullable<Integer>,
        funding_global_index -> Nullable<Integer>,
        funding_commitment_mask -> Nullable<Text>,
        funding_tx_pubkey -> Nullable<Text>,
        amount -> BigInt,
        buyer_signature -> Nullable<Text>,
        vendor_signature -> Nullable<Text>,
        vendor_payout_address -> Nullable<Text>,
        status -> Text,
        buyer_partial_key_image -> Nullable<Text>,
        vendor_partial_key_image -> Nullable<Text>,
        arbiter_partial_key_image -> Nullable<Text>,
        aggregated_key_image -> Nullable<Text>,
        ring_data_json -> Nullable<Text>,
        // MuSig2 nonce columns
        vendor_nonce_public -> Nullable<Text>,
        buyer_nonce_public -> Nullable<Text>,
        nonce_aggregated -> Nullable<Text>,
        // Signed timestamps
        vendor_signed_at -> Nullable<Integer>,
        buyer_signed_at -> Nullable<Integer>,
        first_signer_role -> Nullable<Text>,
    }
}

#[derive(Debug, Clone)]
struct SqlCipherConnectionCustomizer {
    encryption_key: String,
}

impl CustomizeConnection<SqliteConnection, diesel::r2d2::Error> for SqlCipherConnectionCustomizer {
    fn on_acquire(
        &self,
        conn: &mut SqliteConnection,
    ) -> std::result::Result<(), diesel::r2d2::Error> {
        sql_query(format!("PRAGMA key = '{}';", self.encryption_key))
            .execute(conn)
            .map_err(diesel::r2d2::Error::QueryError)?;
        Ok(())
    }
}

fn main() -> Result<()> {
    dotenvy::dotenv().ok();

    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: read_escrow <escrow_id>");
        std::process::exit(1);
    }

    let escrow_id = &args[1];

    let db_url = env::var("DATABASE_URL").unwrap_or_else(|_| "marketplace.db".to_string());
    let encryption_key = env::var("DB_ENCRYPTION_KEY").context("DB_ENCRYPTION_KEY not set")?;

    let manager = ConnectionManager::<SqliteConnection>::new(&db_url);
    let customizer = SqlCipherConnectionCustomizer { encryption_key };
    let pool = r2d2::Pool::builder()
        .max_size(1)
        .connection_customizer(Box::new(customizer))
        .build(manager)?;

    let mut conn = pool.get()?;

    let result: Vec<(
        String,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<i32>,
        Option<i32>,
        Option<String>,
        Option<String>, // funding_tx_pubkey
        i64,
        Option<String>,
        Option<String>,
        Option<String>,
        String,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        // MuSig2 nonce fields
        Option<String>,
        Option<String>,
        Option<String>,
        // Signed timestamps
        Option<i32>,
        Option<i32>,
        Option<String>,
    )> = escrows::table
        .filter(escrows::id.eq(escrow_id))
        .select((
            escrows::id,
            escrows::multisig_address,
            escrows::multisig_view_key,
            escrows::funding_tx_hash,
            escrows::funding_output_index,
            escrows::funding_global_index,
            escrows::funding_commitment_mask,
            escrows::funding_tx_pubkey,
            escrows::amount,
            escrows::buyer_signature,
            escrows::vendor_signature,
            escrows::vendor_payout_address,
            escrows::status,
            escrows::buyer_partial_key_image,
            escrows::vendor_partial_key_image,
            escrows::arbiter_partial_key_image,
            escrows::aggregated_key_image,
            escrows::ring_data_json,
            escrows::vendor_nonce_public,
            escrows::buyer_nonce_public,
            escrows::nonce_aggregated,
            escrows::vendor_signed_at,
            escrows::buyer_signed_at,
            escrows::first_signer_role,
        ))
        .load(&mut conn)?;

    if result.is_empty() {
        eprintln!("No escrow found with ID: {}", escrow_id);
        std::process::exit(1);
    }

    let (
        id,
        addr,
        view_key,
        tx_hash,
        out_idx,
        global_idx,
        mask,
        funding_tx_pk,
        amount,
        buyer_sig,
        vendor_sig,
        payout_addr,
        status,
        buyer_pki,
        vendor_pki,
        arbiter_pki,
        aggregated_ki,
        ring_json,
        vendor_nonce,
        buyer_nonce,
        nonce_agg,
        vendor_signed_ts,
        buyer_signed_ts,
        first_signer_role,
    ) = &result[0];

    println!("=== ESCROW DATA ===");
    println!("First Signer Role: {:?}", first_signer_role);
    println!("Vendor Signed At: {:?}", vendor_signed_ts);
    println!("Buyer Signed At: {:?}", buyer_signed_ts);
    println!("ID: {}", id);
    println!("Status: {}", status);
    println!("Multisig Address: {:?}", addr);
    println!("Multisig View Key: {:?}", view_key);
    println!("Funding TX Hash: {:?}", tx_hash);
    println!("Funding Output Index: {:?}", out_idx);
    println!("Funding Global Index: {:?}", global_idx);
    println!("Funding Commitment Mask: {:?}", mask);
    println!("Funding TX Pubkey (DB column): {:?}", funding_tx_pk);
    println!("Amount: {} atomic ({} XMR)", amount, *amount as f64 / 1e12);
    println!("Vendor Payout Address: {:?}", payout_addr);

    println!("\n=== PARTIAL KEY IMAGES ===");
    println!("Buyer Partial KI: {:?}", buyer_pki);
    println!("Vendor Partial KI: {:?}", vendor_pki);
    println!("Arbiter Partial KI: {:?}", arbiter_pki);
    println!("Aggregated Key Image: {:?}", aggregated_ki);

    println!("\n=== MuSig2 NONCE STATUS ===");
    let has_vendor_nonce = vendor_nonce.is_some();
    let has_buyer_nonce = buyer_nonce.is_some();
    let has_nonce_agg = nonce_agg.is_some();
    println!(
        "Vendor Nonce Public:  {}",
        if has_vendor_nonce {
            "✅ SUBMITTED"
        } else {
            "❌ MISSING"
        }
    );
    println!(
        "Buyer Nonce Public:   {}",
        if has_buyer_nonce {
            "✅ SUBMITTED"
        } else {
            "❌ MISSING"
        }
    );
    println!(
        "Nonces Aggregated:    {}",
        if has_nonce_agg { "✅ YES" } else { "❌ NO" }
    );

    if has_vendor_nonce {
        println!(
            "Vendor Nonce (prefix): {}...",
            vendor_nonce
                .as_ref()
                .map(|n| &n[..32.min(n.len())])
                .unwrap_or("")
        );
    }
    if has_buyer_nonce {
        println!(
            "Buyer Nonce (prefix):  {}...",
            buyer_nonce
                .as_ref()
                .map(|n| &n[..32.min(n.len())])
                .unwrap_or("")
        );
    }
    if has_nonce_agg {
        println!(
            "Aggregated Nonce:      {}...",
            nonce_agg
                .as_ref()
                .map(|n| &n[..64.min(n.len())])
                .unwrap_or("")
        );
    }

    println!("\n=== RING DATA ===");
    if let Some(ring) = ring_json {
        println!("Ring Data Length: {} chars", ring.len());

        // Parse and show keys
        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(ring) {
            if let Some(obj) = parsed.as_object() {
                println!("Ring Data Keys: {:?}", obj.keys().collect::<Vec<_>>());

                // Check for critical fields
                let has_tx_prefix = obj.contains_key("tx_prefix_hash");
                let has_stealth = obj.contains_key("stealth_address");
                let has_tx_pubkey = obj.contains_key("tx_pubkey");
                let has_ring_indices = obj.contains_key("ring_member_indices");

                println!("\n=== CRITICAL FIELDS CHECK ===");
                println!(
                    "tx_prefix_hash:     {}",
                    if has_tx_prefix {
                        "✅ PRESENT"
                    } else {
                        "❌ MISSING"
                    }
                );
                println!(
                    "stealth_address:    {}",
                    if has_stealth {
                        "✅ PRESENT"
                    } else {
                        "❌ MISSING"
                    }
                );
                println!(
                    "tx_pubkey:          {}",
                    if has_tx_pubkey {
                        "✅ PRESENT"
                    } else {
                        "❌ MISSING"
                    }
                );
                println!(
                    "ring_member_indices: {}",
                    if has_ring_indices {
                        "✅ PRESENT"
                    } else {
                        "❌ MISSING"
                    }
                );

                if has_tx_prefix {
                    if let Some(hash) = obj.get("tx_prefix_hash").and_then(|v| v.as_str()) {
                        println!("\ntx_prefix_hash value: {}", hash);
                    }
                }

                // Show signer_index
                if let Some(idx) = obj.get("signer_index") {
                    println!("signer_index: {:?}", idx);
                }

                // Show key_image
                if let Some(ki) = obj.get("key_image").and_then(|v| v.as_str()) {
                    println!("key_image: {}", ki);
                }

                // Show real_global_index
                if let Some(rgi) = obj.get("real_global_index") {
                    println!("real_global_index: {:?}", rgi);
                }

                // Show stealth_address
                if let Some(sa) = obj.get("stealth_address").and_then(|v| v.as_str()) {
                    println!("stealth_address: {}", sa);
                }

                // Show tx_pubkey from ring_data
                if let Some(tp) = obj.get("tx_pubkey").and_then(|v| v.as_str()) {
                    println!("tx_pubkey (ring_data): {}", tp);
                }

                // Show funding_output_pubkey from ring_data
                if let Some(fop) = obj.get("funding_output_pubkey").and_then(|v| v.as_str()) {
                    println!("funding_output_pubkey (ring_data): {}", fop);
                }

                // Show ring_public_keys array
                if let Some(rpk) = obj.get("ring_public_keys").and_then(|v| v.as_array()) {
                    println!("\n=== RING PUBLIC KEYS (P[i]) ===");
                    println!("Ring public keys count: {}", rpk.len());

                    // Get signer_index
                    let signer_idx = obj
                        .get("signer_index")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(15) as usize;

                    println!(
                        "P[{}] (signer position): {}",
                        signer_idx,
                        rpk.get(signer_idx)
                            .and_then(|v| v.as_str())
                            .unwrap_or("MISSING")
                    );

                    // Compare P[signer] with stealth_address and funding_output_pubkey
                    let p_signer = rpk.get(signer_idx).and_then(|v| v.as_str()).unwrap_or("");
                    let stealth = obj
                        .get("stealth_address")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let fop = obj
                        .get("funding_output_pubkey")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");

                    println!("\n=== P[{}] MATCH CHECK ===", signer_idx);
                    println!("P[{}]:                  {}", signer_idx, p_signer);
                    println!("stealth_address:        {}", stealth);
                    println!("funding_output_pubkey:  {}", fop);
                    println!(
                        "P[{}] == stealth_address?       {}",
                        signer_idx,
                        if p_signer == stealth {
                            "✅ YES"
                        } else {
                            "❌ NO"
                        }
                    );
                    println!(
                        "P[{}] == funding_output_pubkey? {}",
                        signer_idx,
                        if p_signer == fop { "✅ YES" } else { "❌ NO" }
                    );
                    println!(
                        "stealth == funding_output_pubkey? {}",
                        if stealth == fop { "✅ YES" } else { "❌ NO" }
                    );
                }
            }
        } else {
            println!(
                "Ring Data (parse failed): {}...",
                &ring[..200.min(ring.len())]
            );
        }
    } else {
        println!("Ring Data: None");
    }

    println!("\n=== SIGNATURES ===");

    // Debug: print vendor_signature JSON
    if let Some(ref sig) = vendor_sig {
        println!("Vendor Signature JSON: {}", sig);
    }

    // Extract c1 from signatures
    fn extract_c1(sig_json: &Option<String>) -> String {
        sig_json
            .as_ref()
            .map(|s| {
                serde_json::from_str::<serde_json::Value>(s)
                    .ok()
                    .and_then(|v| v.get("signature")?.get("c1")?.as_str().map(String::from))
                    .unwrap_or_else(|| "parse error".to_string())
            })
            .unwrap_or_else(|| "None".to_string())
    }

    // Extract s-values array
    fn extract_s_values(sig_json: &Option<String>) -> Vec<String> {
        sig_json
            .as_ref()
            .map(|s| {
                serde_json::from_str::<serde_json::Value>(s)
                    .ok()
                    .and_then(|v| {
                        v.get("signature")?.get("s")?.as_array().map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_str().map(String::from))
                                .collect()
                        })
                    })
                    .unwrap_or_default()
            })
            .unwrap_or_default()
    }

    // Extract D
    fn extract_d(sig_json: &Option<String>) -> String {
        sig_json
            .as_ref()
            .map(|s| {
                serde_json::from_str::<serde_json::Value>(s)
                    .ok()
                    .and_then(|v| v.get("signature")?.get("D")?.as_str().map(String::from))
                    .unwrap_or_else(|| "parse error".to_string())
            })
            .unwrap_or_else(|| "None".to_string())
    }

    let buyer_c1 = extract_c1(buyer_sig);
    let vendor_c1 = extract_c1(vendor_sig);
    let buyer_s = extract_s_values(buyer_sig);
    let vendor_s = extract_s_values(vendor_sig);
    let buyer_d = extract_d(buyer_sig);
    let vendor_d = extract_d(vendor_sig);

    println!("Buyer c1:  {}", buyer_c1);
    println!("Vendor c1: {}", vendor_c1);
    println!(
        "c1 match:  {}",
        if buyer_c1 == vendor_c1 {
            "✅ YES"
        } else {
            "❌ NO"
        }
    );

    println!("\nBuyer D:   {}", buyer_d);
    println!("Vendor D:  {}", vendor_d);
    println!(
        "D match:   {}",
        if buyer_d == vendor_d {
            "✅ YES"
        } else {
            "❌ NO"
        }
    );

    println!("\n=== S-VALUES COMPARISON ===");
    println!("Buyer s count:  {}", buyer_s.len());
    println!("Vendor s count: {}", vendor_s.len());

    if !buyer_s.is_empty() && !vendor_s.is_empty() && buyer_s.len() == vendor_s.len() {
        let mut all_match = true;
        for i in 0..buyer_s.len() {
            let matches = buyer_s[i] == vendor_s[i];
            if !matches {
                all_match = false;
            }
            println!(
                "s[{:2}]: {} {} {}",
                i,
                if matches { "✅" } else { "❌" },
                &buyer_s[i][..16.min(buyer_s[i].len())],
                if !matches {
                    format!("!= {}", &vendor_s[i][..16.min(vendor_s[i].len())])
                } else {
                    String::new()
                }
            );
        }
        if all_match {
            println!("\n✅ ALL s-values match between buyer and vendor");
        } else {
            println!("\n❌ SOME s-values differ - this may indicate aggregation issue");
        }
    }

    // Show full s[15] (real input)
    if buyer_s.len() > 15 {
        println!("\n=== CRITICAL: s[15] (real input) ===");
        println!("Buyer s[15]:  {}", buyer_s[15]);
        println!(
            "Vendor s[15]: {}",
            vendor_s.get(15).unwrap_or(&"N/A".to_string())
        );
    }

    Ok(())
}
