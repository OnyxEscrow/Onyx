// cli/src/checkpoint.rs

use anyhow::Result;
use std::fs;
use std::path::PathBuf;

use monero_marketplace_common::types::Checkpoint;

const CHECKPOINT_DIR: &str = ".checkpoints";

/// Ensures the checkpoint directory exists.
fn ensure_dir_exists() -> Result<PathBuf> {
    let path = PathBuf::from(CHECKPOINT_DIR);
    if !path.exists() {
        fs::create_dir_all(&path)?;
    }
    Ok(path)
}

/// Loads a checkpoint from a file.
pub fn load_checkpoint(session_id: &str) -> Result<Checkpoint> {
    let dir = ensure_dir_exists()?;
    let file_path = dir.join(format!("{}.json", session_id));

    if !file_path.exists() {
        return Ok(Checkpoint::new(session_id.to_string()));
    }

    let content = fs::read_to_string(file_path)?;
    let checkpoint: Checkpoint = serde_json::from_str(&content)?;
    Ok(checkpoint)
}

/// Saves a checkpoint to a file.
pub fn save_checkpoint(checkpoint: &Checkpoint) -> Result<()> {
    let dir = ensure_dir_exists()?;
    let file_path = dir.join(format!("{}.json", checkpoint.session_id));

    let mut updated_checkpoint = checkpoint.clone();
    updated_checkpoint.last_updated = chrono::Utc::now().to_rfc3339();

    let content = serde_json::to_string_pretty(&updated_checkpoint)?;
    fs::write(file_path, content)?;
    Ok(())
}

/// Lists all available checkpoints.
pub fn list_checkpoints() -> Result<Vec<Checkpoint>> {
    let dir = ensure_dir_exists()?;
    let mut checkpoints = Vec::new();

    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("json") {
            let content = fs::read_to_string(path)?;
            let checkpoint: Checkpoint = serde_json::from_str(&content)?;
            checkpoints.push(checkpoint);
        }
    }
    checkpoints.sort_by(|a, b| b.last_updated.cmp(&a.last_updated));
    Ok(checkpoints)
}

/// Deletes a checkpoint file.
pub fn delete_checkpoint(session_id: &str) -> Result<()> {
    let dir = ensure_dir_exists()?;
    let file_path = dir.join(format!("{}.json", session_id));

    if file_path.exists() {
        fs::remove_file(file_path)?;
    }

    Ok(())
}
