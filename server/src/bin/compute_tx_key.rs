use sha3::{Digest, Keccak256};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;

fn main() {
    let escrow_id = "148c8bcd-205d-4f83-8b40-dbfacfcf515e";
    let amount: u64 = 1000000000;

    // Compute tx_secret_key
    let tx_secret_key: [u8; 32] = {
        let mut tx_secret_hasher = Keccak256::new();
        tx_secret_hasher.update(b"NEXUS_TX_SECRET_V1");
        tx_secret_hasher.update(escrow_id.as_bytes());
        tx_secret_hasher.update(&amount.to_le_bytes());
        tx_secret_hasher.finalize().into()
    };

    // Compute tx_pubkey = r * G
    let r = Scalar::from_bytes_mod_order(tx_secret_key);
    let tx_pubkey = (&*ED25519_BASEPOINT_TABLE * &r).compress().to_bytes();

    // Expected tx_pubkey from blockchain (extracted from extra field)
    // Extra: [1, 12, 130, 174, ...] -> bytes 1-32 are the pubkey
    let blockchain_tx_pubkey: [u8; 32] = [
        12, 130, 174, 102, 125, 227, 200, 243, 17, 50, 37, 118, 84, 127, 181, 76,
        85, 59, 227, 231, 52, 28, 99, 1, 220, 56, 236, 13, 1, 120, 51, 117
    ];

    println!("Escrow ID: {}", escrow_id);
    println!("Amount: {} atomic", amount);
    println!();
    println!("tx_secret_key:            {}", hex::encode(&tx_secret_key));
    println!();
    println!("Computed tx_pubkey (r*G): {}", hex::encode(&tx_pubkey));
    println!("Blockchain tx_pubkey:     {}", hex::encode(&blockchain_tx_pubkey));
    println!();
    println!("TX PUBKEYS MATCH? {}", tx_pubkey == blockchain_tx_pubkey);
}
