// Verify encrypted_amount for output[1] (platform fee)
// Using the EXACT algorithm from transaction_builder.rs

use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::scalar::Scalar;
use sha3::{Digest, Keccak256};

fn main() {
    println!("=== VERIFY ENCRYPTED AMOUNT FOR OUTPUT[1] ===\n");

    // Known values from escrow 148c8bcd-205d-4f83-8b40-dbfacfcf515e
    let escrow_id = "148c8bcd-205d-4f83-8b40-dbfacfcf515e";
    let amount: u64 = 1000000000; // 1 XMR in atomic
    let platform_fee: u64 = 50000000; // 5% of input = 0.05 XMR

    // Platform view public key (from address 58WZH...)
    let platform_view_pub_hex = "88141fed8ba6befc00a338fa0d7080fadd8576626b7d2f5dc1a5627b762a40f2";
    let platform_view_pub: [u8; 32] = hex::decode(platform_view_pub_hex)
        .expect("Invalid platform_view_pub hex")
        .try_into()
        .expect("Invalid length");

    // TX pubkey from blockchain (R = r*G)
    let tx_pubkey_hex = "0c82ae667de3c8f311322576547fb54c553be3e7341c6301dc38ec0d01783375";

    // Encrypted amount from blockchain for output[1]
    let encrypted_amount_hex = "57d221f5f19b3220";
    let encrypted_amount_bytes: [u8; 8] = hex::decode(encrypted_amount_hex)
        .expect("Invalid encrypted_amount hex")
        .try_into()
        .expect("Invalid length");

    println!("Platform fee expected: {} atomic", platform_fee);
    println!("Encrypted amount from blockchain: {}", encrypted_amount_hex);
    println!();

    // ================================================================
    // SENDER SIDE: Using transaction_builder.rs algorithm
    // ================================================================
    println!("=== SENDER SIDE (transaction_builder.rs algorithm) ===\n");

    // Step 1: Compute tx_secret_key (deterministic)
    let tx_secret_key: [u8; 32] = {
        let mut hasher = Keccak256::new();
        hasher.update(b"NEXUS_TX_SECRET_V1");
        hasher.update(escrow_id.as_bytes());
        hasher.update(&amount.to_le_bytes());
        hasher.finalize().into()
    };
    println!("tx_secret_key (r): {}", hex::encode(&tx_secret_key));

    // Step 2: Compute derivation = 8 * r * V
    let r = Scalar::from_bytes_mod_order(tx_secret_key);
    let view_pub_point = CompressedEdwardsY(platform_view_pub)
        .decompress()
        .expect("Failed to decompress platform_view_pub");

    let derivation = (r * view_pub_point).mul_by_cofactor();
    let derivation_bytes = derivation.compress().to_bytes();
    println!("derivation (8*r*V): {}", hex::encode(&derivation_bytes));

    // Output index for platform fee
    let output_index: u64 = 1;

    // Step 3: derivation_to_scalar = Hs(derivation || varint(output_index))
    let mut derivation_input = derivation_bytes.to_vec();
    let mut idx = output_index;
    while idx >= 0x80 {
        derivation_input.push((idx as u8 & 0x7f) | 0x80);
        idx >>= 7;
    }
    derivation_input.push(idx as u8);

    let shared_sec_hash: [u8; 32] = Keccak256::digest(&derivation_input).into();
    let shared_sec = Scalar::from_bytes_mod_order(shared_sec_hash); // sc_reduce32
    let shared_sec_bytes = shared_sec.to_bytes();
    println!(
        "shared_sec (Hs(derivation || varint(1))): {}",
        hex::encode(&shared_sec_bytes)
    );

    // Step 4: encoding_factor = Keccak256("amount" || sharedSec)
    let mut amount_hasher = Keccak256::new();
    amount_hasher.update(b"amount"); // 6-byte domain separator
    amount_hasher.update(&shared_sec_bytes);
    let encoding_factor: [u8; 32] = amount_hasher.finalize().into();
    let mask: [u8; 8] = encoding_factor[0..8].try_into().unwrap();
    println!("encoding_factor[0:8]: {}", hex::encode(&mask));

    // Step 5: encrypted_amount = amount XOR encoding_factor[0:8]
    let platform_fee_bytes = platform_fee.to_le_bytes();
    let mut computed_encrypted = [0u8; 8];
    for i in 0..8 {
        computed_encrypted[i] = platform_fee_bytes[i] ^ mask[i];
    }
    println!(
        "\nComputed encrypted_amount: {}",
        hex::encode(&computed_encrypted)
    );
    println!("Blockchain encrypted_amount: {}", encrypted_amount_hex);

    if hex::encode(&computed_encrypted) == encrypted_amount_hex {
        println!("✅ MATCH! transaction_builder.rs produces correct encrypted_amount");
    } else {
        println!("❌ NO MATCH - transaction_builder.rs algorithm doesn't match blockchain");
    }

    // ================================================================
    // RECIPIENT SIDE: Using wallet's view secret key
    // ================================================================
    println!("\n=== RECIPIENT SIDE (wallet decryption) ===\n");

    // Platform view SECRET key (from user)
    let view_secret_hex = "4780bc9bed77502d2f5a6cea05b24edfeb7a115118c1f58d9e98b10bf2f15505";
    let view_secret_bytes: [u8; 32] = hex::decode(view_secret_hex)
        .expect("Invalid view_secret hex")
        .try_into()
        .expect("Invalid length");

    let tx_pubkey_bytes: [u8; 32] = hex::decode(tx_pubkey_hex)
        .expect("Invalid tx_pubkey hex")
        .try_into()
        .expect("Invalid length");

    // Recipient derivation = 8 * v * R
    let v = Scalar::from_bytes_mod_order(view_secret_bytes);
    let tx_pubkey_point = CompressedEdwardsY(tx_pubkey_bytes)
        .decompress()
        .expect("Failed to decompress tx_pubkey");

    let recipient_derivation = (v * tx_pubkey_point).mul_by_cofactor();
    let recipient_derivation_bytes = recipient_derivation.compress().to_bytes();
    println!(
        "recipient derivation (8*v*R): {}",
        hex::encode(&recipient_derivation_bytes)
    );

    if derivation_bytes == recipient_derivation_bytes {
        println!("✅ Derivations match (sender = recipient)");
    } else {
        println!("❌ Derivations DON'T match!");
        println!("   sender:    {}", hex::encode(&derivation_bytes));
        println!("   recipient: {}", hex::encode(&recipient_derivation_bytes));
    }

    // Recipient shared_sec = Hs(derivation || varint(1))
    let mut recipient_derivation_input = recipient_derivation_bytes.to_vec();
    let mut idx2 = output_index;
    while idx2 >= 0x80 {
        recipient_derivation_input.push((idx2 as u8 & 0x7f) | 0x80);
        idx2 >>= 7;
    }
    recipient_derivation_input.push(idx2 as u8);

    let recipient_shared_sec_hash: [u8; 32] = Keccak256::digest(&recipient_derivation_input).into();
    let recipient_shared_sec = Scalar::from_bytes_mod_order(recipient_shared_sec_hash);
    let recipient_shared_sec_bytes = recipient_shared_sec.to_bytes();
    println!(
        "recipient shared_sec: {}",
        hex::encode(&recipient_shared_sec_bytes)
    );

    // Recipient encoding_factor = H("amount" || shared_sec)
    let mut recipient_amount_hasher = Keccak256::new();
    recipient_amount_hasher.update(b"amount");
    recipient_amount_hasher.update(&recipient_shared_sec_bytes);
    let recipient_encoding_factor: [u8; 32] = recipient_amount_hasher.finalize().into();
    let recipient_mask: [u8; 8] = recipient_encoding_factor[0..8].try_into().unwrap();
    println!(
        "recipient encoding_factor[0:8]: {}",
        hex::encode(&recipient_mask)
    );

    // Decrypt blockchain's encrypted_amount using recipient's mask
    let mut decrypted = [0u8; 8];
    for i in 0..8 {
        decrypted[i] = encrypted_amount_bytes[i] ^ recipient_mask[i];
    }
    let decrypted_amount = u64::from_le_bytes(decrypted);
    println!(
        "\nDecrypted amount from blockchain: {} atomic",
        decrypted_amount
    );
    println!("Expected platform fee: {} atomic", platform_fee);

    if decrypted_amount == platform_fee {
        println!(
            "✅ AMOUNT MATCHES! Wallet should see {} atomic",
            platform_fee
        );
    } else {
        println!("❌ AMOUNT DOESN'T MATCH!");
        println!("   The wallet decrypts garbage instead of the real amount.");
    }

    // ================================================================
    // DIAGNOSE: What amount does the blockchain's encrypted_amount decode to
    // if we use the CORRECT mask?
    // ================================================================
    println!("\n=== DIAGNOSIS ===\n");

    println!("If the wallet can see this output (stealth_address matches),");
    println!("and check_tx_key says 'received nothing', then:");
    println!("  - Either the commitment doesn't match the amount");
    println!("  - Or the encrypted_amount was computed with WRONG parameters");

    // What mask was used to encrypt the blockchain value?
    // encrypted = amount XOR mask
    // => mask = encrypted XOR amount
    let reverse_mask = [
        encrypted_amount_bytes[0] ^ platform_fee_bytes[0],
        encrypted_amount_bytes[1] ^ platform_fee_bytes[1],
        encrypted_amount_bytes[2] ^ platform_fee_bytes[2],
        encrypted_amount_bytes[3] ^ platform_fee_bytes[3],
        encrypted_amount_bytes[4] ^ platform_fee_bytes[4],
        encrypted_amount_bytes[5] ^ platform_fee_bytes[5],
        encrypted_amount_bytes[6] ^ platform_fee_bytes[6],
        encrypted_amount_bytes[7] ^ platform_fee_bytes[7],
    ];
    println!(
        "\nReverse-engineered mask (encrypted XOR amount): {}",
        hex::encode(&reverse_mask)
    );
    println!(
        "Expected mask (transaction_builder algorithm):   {}",
        hex::encode(&mask)
    );

    if reverse_mask == mask {
        println!("✅ Masks match - encrypted_amount is correctly computed");
    } else {
        println!("❌ Masks DON'T match - encrypted_amount was computed with DIFFERENT parameters!");
        println!("   This means either:");
        println!("   1. Different tx_secret_key was used");
        println!("   2. Different view_pub was used");
        println!("   3. Different output_index was used");
        println!("   4. Different amount was used");
    }
}
