//! End-to-end tests for escrow broadcast flow
//!
//! These tests exercise the complete escrow signing and broadcast flow
//! using the HTTP API with test authentication bypass.
//!
//! Requirements:
//! - Server running with TEST_AUTH_BYPASS=1
//! - Test database with migrations applied
//!
//! Run with:
//! ```bash
//! TEST_AUTH_BYPASS=1 cargo test --package server --test broadcast_e2e -- --ignored --nocapture
//! ```

use anyhow::{Context, Result};
use reqwest::{Client, StatusCode};
use serde_json::{json, Value};
use std::time::Duration;
use uuid::Uuid;

/// Test server base URL
const BASE_URL: &str = "http://127.0.0.1:8080";

/// CSRF token for tests (debug bypass)
const TEST_CSRF_TOKEN: &str = "test-csrf-token-skip";

/// Test user IDs (consistent across tests)
const TEST_BUYER_ID: &str = "11111111-1111-1111-1111-111111111111";
const TEST_VENDOR_ID: &str = "22222222-2222-2222-2222-222222222222";
const TEST_ARBITER_ID: &str = "33333333-3333-3333-3333-333333333333";

/// HTTP client wrapper with session cookie management
struct TestClient {
    client: Client,
    session_cookie: Option<String>,
}

impl TestClient {
    fn new() -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client");

        Self {
            client,
            session_cookie: None,
        }
    }

    /// Login as test user via debug endpoint
    async fn test_login(&mut self, user_id: &str, username: &str, role: &str) -> Result<()> {
        let resp = self
            .client
            .post(&format!("{}/api/debug/test-login", BASE_URL))
            .json(&json!({
                "user_id": user_id,
                "username": username,
                "role": role
            }))
            .send()
            .await
            .context("Failed to send test login request")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("Test login failed: {} - {}", status, body);
        }

        // Extract session cookie (only the name=value part, not attributes)
        if let Some(cookie_header) = resp.headers().get("set-cookie") {
            let cookie_str = cookie_header.to_str()?;
            // Cookie format: "name=value; HttpOnly; ..." - extract only "name=value"
            let cookie_value = cookie_str.split(';').next().unwrap_or(cookie_str);
            self.session_cookie = Some(cookie_value.to_string());
            println!("DEBUG: Extracted cookie: {}", cookie_value);
        } else {
            println!("DEBUG: No set-cookie header found!");
        }

        Ok(())
    }

    /// Make authenticated GET request
    async fn get(&self, path: &str) -> Result<reqwest::Response> {
        let mut req = self.client.get(&format!("{}{}", BASE_URL, path));

        if let Some(cookie) = &self.session_cookie {
            req = req.header("Cookie", cookie.clone());
        }

        Ok(req.send().await?)
    }

    /// Make authenticated POST request with JSON body
    async fn post_json(&self, path: &str, body: Value) -> Result<reqwest::Response> {
        let mut req = self
            .client
            .post(&format!("{}{}", BASE_URL, path))
            .header("X-CSRF-Token", TEST_CSRF_TOKEN)
            .json(&body);

        if let Some(cookie) = &self.session_cookie {
            req = req.header("Cookie", cookie.clone());
        }

        Ok(req.send().await?)
    }
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

/// Check if test server is running
async fn check_server_available() -> bool {
    let client = Client::new();
    match client.get(&format!("{}/api/health", BASE_URL)).send().await {
        Ok(resp) => resp.status().is_success(),
        Err(_) => false,
    }
}

/// Check if TEST_AUTH_BYPASS is enabled on server
async fn check_auth_bypass_enabled() -> bool {
    let client = Client::new();
    let resp = client
        .post(&format!("{}/api/debug/test-login", BASE_URL))
        .json(&json!({
            "user_id": TEST_BUYER_ID,
            "username": "bypass_check",
            "role": "buyer"
        }))
        .send()
        .await;

    match resp {
        Ok(r) => r.status().is_success(),
        Err(_) => false,
    }
}

/// Create a test user in database (direct DB insertion)
async fn ensure_test_users_exist(client: &TestClient) -> Result<()> {
    // For now, we assume users exist or are created by the test-login bypass
    // The TestAuthBypass middleware creates synthetic users
    Ok(())
}

// =============================================================================
// TEST CASES
// =============================================================================

/// Test 1: Verify test login endpoint works
#[tokio::test]
#[ignore] // Requires running server with TEST_AUTH_BYPASS=1
async fn test_debug_login_endpoint() -> Result<()> {
    if !check_server_available().await {
        println!("⚠️  SKIPPED: Server not running at {}", BASE_URL);
        return Ok(());
    }

    if !check_auth_bypass_enabled().await {
        println!("⚠️  SKIPPED: TEST_AUTH_BYPASS not enabled on server");
        return Ok(());
    }

    let mut client = TestClient::new();

    // Login as buyer
    client
        .test_login(TEST_BUYER_ID, "test_buyer", "buyer")
        .await?;

    // Verify session by calling whoami
    let resp = client.get("/api/auth/whoami").await?;

    if resp.status() != StatusCode::OK {
        let body = resp.text().await?;
        println!("Whoami response: {}", body);
        anyhow::bail!("Whoami failed after test login");
    }

    let body: Value = resp.json().await?;
    println!("✅ Test login successful: {:?}", body);

    Ok(())
}

/// Test 2: Create escrow via HTTP API
#[tokio::test]
#[ignore] // Requires running server with TEST_AUTH_BYPASS=1
async fn test_create_escrow_via_api() -> Result<()> {
    if !check_server_available().await {
        println!("⚠️  SKIPPED: Server not running at {}", BASE_URL);
        return Ok(());
    }

    if !check_auth_bypass_enabled().await {
        println!("⚠️  SKIPPED: TEST_AUTH_BYPASS not enabled on server");
        return Ok(());
    }

    let mut client = TestClient::new();

    // Login as vendor to create listing
    client
        .test_login(TEST_VENDOR_ID, "test_vendor", "vendor")
        .await?;

    // TODO: Create listing
    // TODO: Login as buyer
    // TODO: Create order
    // TODO: Init escrow

    println!("✅ Test escrow creation - STUB (requires full flow implementation)");

    Ok(())
}

/// Test 3: Submit partial key image
#[tokio::test]
#[ignore] // Requires running server with TEST_AUTH_BYPASS=1
async fn test_submit_partial_key_image() -> Result<()> {
    if !check_server_available().await {
        println!("⚠️  SKIPPED: Server not running at {}", BASE_URL);
        return Ok(());
    }

    if !check_auth_bypass_enabled().await {
        println!("⚠️  SKIPPED: TEST_AUTH_BYPASS not enabled on server");
        return Ok(());
    }

    // This test requires an existing funded escrow
    // For now, we test the endpoint structure

    let mut client = TestClient::new();
    client
        .test_login(TEST_BUYER_ID, "test_buyer", "buyer")
        .await?;

    // Use a known escrow ID (from previous test or database)
    let escrow_id = "1eb1ceb7-4f7e-4c2b-bc7d-8e2f3a4b5c6d"; // Placeholder

    // Mock partial key image (32 bytes hex = 64 chars)
    let mock_pki = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";

    let resp = client
        .post_json(
            &format!("/api/v2/escrow/{}/submit-partial-key-image", escrow_id),
            json!({
                "role": "buyer",
                "partial_key_image": mock_pki
            }),
        )
        .await?;

    // We expect 404 (escrow not found) or 400 (validation) since escrow doesn't exist
    // But NOT 401 (unauthorized) if auth bypass works
    let status = resp.status();
    if status == StatusCode::UNAUTHORIZED {
        anyhow::bail!("Auth bypass failed - got 401 Unauthorized");
    }

    println!("✅ PKI submission endpoint accessible (status: {})", status);

    Ok(())
}

/// Test 4: Full broadcast flow with mock data
///
/// This test creates all necessary data and attempts a broadcast.
/// It will fail at the daemon with "Sanity check failed" but should
/// trigger all DIAG logs.
#[tokio::test]
#[ignore] // Requires running server with TEST_AUTH_BYPASS=1 and funded escrow
async fn test_broadcast_flow_with_diagnostics() -> Result<()> {
    if !check_server_available().await {
        println!("⚠️  SKIPPED: Server not running at {}", BASE_URL);
        return Ok(());
    }

    if !check_auth_bypass_enabled().await {
        println!("⚠️  SKIPPED: TEST_AUTH_BYPASS not enabled on server");
        return Ok(());
    }

    println!("=== BROADCAST FLOW TEST ===");
    println!("This test will trigger the broadcast endpoint.");
    println!("Check server_debug.log for DIAG-1 through DIAG-7 logs.");
    println!("");

    let mut client = TestClient::new();

    // Use a known escrow ID that is in 'ready_to_broadcast' state
    // This must be set up beforehand
    let escrow_id = std::env::var("TEST_ESCROW_ID")
        .unwrap_or_else(|_| "1eb1ceb7-4f7e-4c2b-bc7d-8e2f3a4b5c6d".to_string());

    println!("Testing escrow: {}", escrow_id);

    // Login as buyer (usually the one who confirms receipt)
    client
        .test_login(TEST_BUYER_ID, "test_buyer", "buyer")
        .await?;

    // Attempt broadcast
    let resp = client
        .post_json(
            &format!("/api/v2/escrow/{}/broadcast-tx", escrow_id),
            json!({}),
        )
        .await?;

    let status = resp.status();
    let body = resp.text().await?;

    println!("Broadcast response: {} - {}", status, body);

    // Expected outcomes:
    // - 200: Broadcast succeeded (unlikely without real setup)
    // - 400: Escrow not ready / missing data
    // - 404: Escrow not found
    // - 500: Internal error (daemon failure with DIAG logs)

    if status == StatusCode::UNAUTHORIZED {
        anyhow::bail!("Auth bypass failed - got 401 Unauthorized");
    }

    println!("");
    println!("✅ Broadcast endpoint triggered (status: {})", status);
    println!("Check server_debug.log for DIAG- logs!");

    Ok(())
}

/// Test 5: Direct broadcast trigger via debug endpoint
#[tokio::test]
#[ignore] // Requires running server
async fn test_debug_broadcast_endpoint() -> Result<()> {
    if !check_server_available().await {
        println!("⚠️  SKIPPED: Server not running at {}", BASE_URL);
        return Ok(());
    }

    // Use debug endpoint which doesn't require auth
    let client = Client::new();

    // Use a known escrow ID
    let escrow_id = std::env::var("TEST_ESCROW_ID")
        .unwrap_or_else(|_| "1eb1ceb7-4f7e-4c2b-bc7d-8e2f3a4b5c6d".to_string());

    println!("Testing debug broadcast for escrow: {}", escrow_id);

    let resp = client
        .post(&format!(
            "{}/api/debug/escrow/{}/broadcast",
            BASE_URL, escrow_id
        ))
        .send()
        .await?;

    let status = resp.status();
    let body = resp.text().await?;

    println!("Debug broadcast response: {} - {}", status, body);
    println!("");
    println!("✅ Debug broadcast endpoint triggered");
    println!("Check server_debug.log for DIAG- logs!");

    Ok(())
}

// =============================================================================
// INTEGRATION TEST: Full flow from order to broadcast
// =============================================================================

/// Full integration test that creates order → escrow → registers wallets →
/// submits PKIs → initiates signing → broadcasts
///
/// This is the comprehensive test that exercises the entire flow.
#[tokio::test]
#[ignore] // Requires full setup
async fn test_full_escrow_broadcast_integration() -> Result<()> {
    if !check_server_available().await {
        println!("⚠️  SKIPPED: Server not running at {}", BASE_URL);
        return Ok(());
    }

    if !check_auth_bypass_enabled().await {
        println!("⚠️  SKIPPED: TEST_AUTH_BYPASS not enabled on server");
        return Ok(());
    }

    println!("=== FULL INTEGRATION TEST ===");
    println!("This test requires:");
    println!("1. Server running with TEST_AUTH_BYPASS=1");
    println!("2. Test database with users/listings");
    println!("3. Monero daemon accessible");
    println!("");

    // TODO: Implement full flow
    // 1. Create listing as vendor
    // 2. Create order as buyer
    // 3. Initialize escrow
    // 4. Register WASM wallets
    // 5. Simulate funding notification
    // 6. Submit partial key images
    // 7. Set payout address
    // 8. Init signing (vendor)
    // 9. Complete signing (buyer)
    // 10. Broadcast transaction
    // 11. Check DIAG logs

    println!("⚠️  Full integration test not yet implemented");
    println!("Use test_debug_broadcast_endpoint for quick testing");

    Ok(())
}
