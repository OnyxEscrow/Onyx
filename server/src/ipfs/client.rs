//! IPFS client for uploading and retrieving reputation files
//!
//! This module provides a production-ready IPFS client with:
//! - Automatic retry logic with exponential backoff
//! - Connection pooling
//! - Timeout handling
//! - Support for local node (localhost:5001) or Infura gateway
//! - Proper error handling (no panics)

use anyhow::{Context, Result};
use base64::Engine;
use reqwest::{multipart, Proxy};
use serde::Deserialize;
use std::time::Duration;

/// Maximum retries for IPFS operations
const MAX_RETRIES: u32 = 3;

/// Request timeout in seconds
const REQUEST_TIMEOUT_SECS: u64 = 30;

/// IPFS client for uploading/downloading files
///
/// Supports both local IPFS node and Infura gateway.
#[derive(Clone)]
pub struct IpfsClient {
    /// HTTP client with connection pooling
    client: reqwest::Client,

    /// Base URL for IPFS API (e.g., http://localhost:5001/api/v0)
    api_base_url: String,

    /// Gateway URL for retrieving files (e.g., http://localhost:8081/ipfs)
    gateway_url: String,
}

/// Response from IPFS add operation
#[derive(Debug, Deserialize)]
struct IpfsAddResponse {
    #[serde(rename = "Hash")]
    hash: String,

    #[serde(rename = "Name")]
    #[allow(dead_code)]
    name: String,

    #[serde(rename = "Size")]
    #[allow(dead_code)]
    size: String,
}

impl IpfsClient {
    /// Create a new IPFS client
    ///
    /// # Arguments
    /// * `api_url` - IPFS API URL (default: http://localhost:5001/api/v0)
    /// * `gateway_url` - IPFS Gateway URL (default: http://localhost:8081/ipfs)
    ///
    /// # Example
    /// ```no_run
    /// let client = IpfsClient::new(
    ///     "http://localhost:5001/api/v0".to_string(),
    ///     "http://localhost:8081/ipfs".to_string()
    /// )?;
    /// ```
    pub fn new(api_url: String, gateway_url: String) -> Result<Self> {
        // Build HTTP client with optional Tor proxy
        let mut client_builder = reqwest::Client::builder()
            .timeout(Duration::from_secs(REQUEST_TIMEOUT_SECS))
            .pool_max_idle_per_host(10);

        // SECURITY: Route all IPFS traffic through Tor in production
        // For development, set IPFS_USE_TOR=false to disable Tor proxy
        if api_url.starts_with("http://127.0.0.1") || api_url.starts_with("http://localhost") {
            tracing::info!("IPFS: Connecting directly to local IPFS node (Tor proxy bypassed for local connection)");
        } else {
            tracing::info!("IPFS: Configuring Tor SOCKS5 proxy (127.0.0.1:9050)");
            let proxy = Proxy::all("socks5://127.0.0.1:9050")
                .context("Failed to configure Tor SOCKS5 proxy for IPFS")?;
            client_builder = client_builder.proxy(proxy);
        }

        let client = client_builder
            .build()
            .context("Failed to build HTTP client")?;

        Ok(Self {
            client,
            api_base_url: api_url,
            gateway_url,
        })
    }

    /// Create client with default local IPFS node settings
    ///
    /// Connects to localhost:5001 (API) and localhost:8083 (gateway)
    pub fn new_local() -> Result<Self> {
        Self::new(
            "http://127.0.0.1:5001/api/v0".to_string(),
            "http://127.0.0.1:8083/ipfs".to_string(),
        )
    }

    /// Create client for Infura IPFS gateway
    ///
    /// # Arguments
    /// * `project_id` - Infura project ID
    /// * `project_secret` - Infura project secret
    ///
    /// Note: Requires authentication with Infura credentials
    pub fn new_infura(project_id: String, project_secret: String) -> Result<Self> {
        use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION};

        // Manually construct Basic Auth header (reqwest's basic_auth not available in this version)
        let auth_value = format!("{}:{}", project_id, project_secret);
        let encoded = base64::engine::general_purpose::STANDARD.encode(auth_value.as_bytes());
        let header_value = format!("Basic {}", encoded);

        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&header_value)
                .context("Failed to create authorization header")?,
        );

        // SECURITY: Route all IPFS traffic through Tor to prevent IP leaks
        let proxy = Proxy::all("socks5h://127.0.0.1:9050")
            .context("Failed to configure Tor SOCKS5 proxy for IPFS")?;

        let client = reqwest::Client::builder()
            .proxy(proxy)
            .timeout(Duration::from_secs(REQUEST_TIMEOUT_SECS))
            .pool_max_idle_per_host(10)
            .default_headers(headers)
            .build()
            .context("Failed to build HTTP client with authentication")?;

        Ok(Self {
            client,
            api_base_url: "https://ipfs.infura.io:5001/api/v0".to_string(),
            gateway_url: "https://ipfs.io/ipfs".to_string(),
        })
    }

    /// Upload data to IPFS
    ///
    /// # Arguments
    /// * `data` - Bytes to upload
    ///
    /// # Returns
    /// IPFS content hash (CID), e.g., "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG"
    ///
    /// # Errors
    /// - Network errors (connection refused, timeout)
    /// - IPFS node errors (daemon not running, disk full)
    /// - Serialization errors
    ///
    /// # Performance
    /// - Uses multipart/form-data encoding
    /// - Automatically retries on transient failures (up to MAX_RETRIES)
    /// - Connection pooling for efficiency
    pub async fn add(&self, data: Vec<u8>, file_name: &str, mime_type: &str) -> Result<String> {
        let mut attempt = 0;

        loop {
            attempt += 1;

            match self.add_internal(&data, file_name, mime_type).await {
                Ok(hash) => {
                    tracing::info!(
                        hash = %hash,
                        size = data.len(),
                        attempt = attempt,
                        "IPFS upload successful"
                    );
                    return Ok(hash);
                }
                Err(e) if attempt < MAX_RETRIES => {
                    let backoff_ms = 2u64.pow(attempt) * 100; // Exponential backoff
                    tracing::warn!(
                        error = %e,
                        attempt = attempt,
                        backoff_ms = backoff_ms,
                        "IPFS upload failed, retrying..."
                    );
                    tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                }
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        attempts = attempt,
                        "IPFS upload failed after all retries"
                    );
                    return Err(e).context("IPFS upload failed after retries");
                }
            }
        }
    }

    /// Internal implementation of IPFS add (single attempt)
    async fn add_internal(&self, data: &[u8], file_name: &str, mime_type: &str) -> Result<String> {
        let form = multipart::Form::new().part(
            "file",
            multipart::Part::bytes(data.to_vec())
                .file_name(file_name.to_string())
                .mime_str(mime_type)
                .context("Failed to set MIME type")?,
        );

        let url = format!("{}/add", self.api_base_url);

        let response = self
            .client
            .post(&url)
            .multipart(form)
            .send()
            .await
            .context("Failed to send IPFS add request")?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "<failed to read body>".to_string());

            anyhow::bail!("IPFS add failed with status {}: {}", status, body);
        }

        let add_response: IpfsAddResponse = response
            .json()
            .await
            .context("Failed to parse IPFS add response")?;

        Ok(add_response.hash)
    }

    /// Download data from IPFS
    ///
    /// # Arguments
    /// * `hash` - IPFS content hash (CID)
    ///
    /// # Returns
    /// Raw bytes from IPFS
    ///
    /// # Errors
    /// - Network errors
    /// - Content not found (404)
    /// - Gateway timeout
    pub async fn cat(&self, hash: &str) -> Result<Vec<u8>> {
        let mut attempt = 0;

        loop {
            attempt += 1;

            match self.cat_internal(hash).await {
                Ok(data) => {
                    tracing::debug!(
                        hash = %hash,
                        size = data.len(),
                        "IPFS download successful"
                    );
                    return Ok(data);
                }
                Err(e) if attempt < MAX_RETRIES => {
                    let backoff_ms = 2u64.pow(attempt) * 100;
                    tracing::warn!(
                        error = %e,
                        hash = %hash,
                        attempt = attempt,
                        "IPFS download failed, retrying..."
                    );
                    tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                }
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        hash = %hash,
                        attempts = attempt,
                        "IPFS download failed after all retries"
                    );
                    return Err(e).context("IPFS download failed after retries");
                }
            }
        }
    }

    /// Internal implementation of IPFS cat (single attempt)
    async fn cat_internal(&self, hash: &str) -> Result<Vec<u8>> {
        let url = format!("{}/{}", self.gateway_url, hash);

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .context("Failed to send IPFS cat request")?;

        if !response.status().is_success() {
            let status = response.status();
            anyhow::bail!("IPFS cat failed with status {}", status);
        }

        let bytes = response
            .bytes()
            .await
            .context("Failed to read IPFS response body")?;

        Ok(bytes.to_vec())
    }

    /// Check if IPFS node is reachable
    ///
    /// # Returns
    /// `true` if IPFS daemon is running and accessible, `false` otherwise
    pub async fn is_available(&self) -> bool {
        let url = format!("{}/version", self.api_base_url);

        match self.client.post(&url).send().await {
            Ok(response) => response.status().is_success(),
            Err(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_ipfs_client_creation() {
        let client = IpfsClient::new_local();
        assert!(client.is_ok());
    }

    // Note: Integration tests with real IPFS node in server/tests/ipfs_integration.rs
}
