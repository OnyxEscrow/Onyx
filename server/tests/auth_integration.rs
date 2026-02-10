//! Integration tests for authentication endpoints
//!
//! Tests the complete auth flow with real database and session management.
//! No mocks - production-ready testing against actual services.

use actix_session::{config::PersistentSession, storage::CookieSessionStore, SessionMiddleware};
use actix_web::{cookie::Key, middleware::Logger, test, web, App};
use diesel::r2d2::{self, ConnectionManager};
use diesel::SqliteConnection;
use serde_json::json;
use time::Duration;

use server::{db::create_pool, handlers::auth};

type DbPool = r2d2::Pool<ConnectionManager<SqliteConnection>>;

/// Helper function to create a CSRF token for testing
///
/// Returns the special bypass token that is accepted in debug builds.
/// This allows integration tests to bypass CSRF validation without complex session setup.
/// The bypass is ONLY enabled in debug_assertions builds (removed in release).
fn create_test_csrf_token() -> String {
    "test-csrf-token-skip".to_string()
}

/// Helper function to create test app with all middleware
fn create_test_app(
    pool: DbPool,
) -> App<
    impl actix_web::dev::ServiceFactory<
        actix_web::dev::ServiceRequest,
        Config = (),
        Response = actix_web::dev::ServiceResponse<impl actix_web::body::MessageBody>,
        Error = actix_web::Error,
        InitError = (),
    >,
> {
    let secret_key = Key::from(b"test_secret_key_at_least_64_bytes_long_for_security_purposes!!!!");

    App::new()
        .wrap(Logger::default())
        .wrap(
            SessionMiddleware::builder(CookieSessionStore::default(), secret_key.clone())
                .cookie_name("test_session".to_string())
                .cookie_http_only(true)
                .cookie_same_site(actix_web::cookie::SameSite::Strict)
                .session_lifecycle(PersistentSession::default().session_ttl(Duration::hours(24)))
                .build(),
        )
        .app_data(web::Data::new(pool.clone()))
        .service(
            web::scope("/api/auth")
                .service(auth::register)
                .service(auth::login)
                .service(auth::whoami)
                .service(auth::logout),
        )
}

/// Test 1: Complete auth flow (register → login)
///
/// # Test Coverage
/// - User registration with valid data
/// - Login with correct credentials
/// - Verify response bodies contain correct data
#[actix_web::test]
async fn test_complete_auth_flow() -> Result<(), Box<dyn std::error::Error>> {
    // Setup: Create in-memory test database
    let pool = create_pool(":memory:", "test_encryption_key_32_bytes!!")?;

    // Run migrations
    {
        use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};
        const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations");
        let mut conn = pool.get()?;
        conn.run_pending_migrations(MIGRATIONS)
            .expect("Failed to run migrations");
    }

    let app = test::init_service(create_test_app(pool)).await;

    // Step 1: Register new user
    let csrf_token = create_test_csrf_token();

    let register_payload = json!({
        "username": "alice_test",
        "password": "securepassword123",
        "role": "buyer",
        "csrf_token": csrf_token
    });

    let req = test::TestRequest::post()
        .uri("/register")
        .set_form(&register_payload)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 201, "Registration should succeed");

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["username"], "alice_test");
    assert_eq!(body["role"], "buyer");
    assert!(body["id"].is_string(), "Should return user ID");
    assert!(
        body.get("password_hash").is_none(),
        "Should not expose password_hash"
    );

    // Step 2: Login with correct credentials
    let login_payload = json!({
        "username": "alice_test",
        "password": "securepassword123"
    });

    let req = test::TestRequest::post()
        .uri("/login")
        .set_form(&login_payload)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200, "Login should succeed");

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["username"], "alice_test");
    assert_eq!(body["role"], "buyer");

    Ok(())
}

/// Test 2: Invalid credentials
///
/// # Test Coverage
/// - Login with non-existent username
/// - Login with wrong password
/// - Verify 401 Unauthorized response
#[actix_web::test]
async fn test_invalid_credentials() -> Result<(), Box<dyn std::error::Error>> {
    let pool = create_pool(":memory:", "test_encryption_key_32_bytes!!")?;

    // Run migrations
    {
        use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};
        const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations");
        let mut conn = pool.get()?;
        conn.run_pending_migrations(MIGRATIONS)
            .expect("Failed to run migrations");
    }

    let app = test::init_service(create_test_app(pool.clone())).await;

    // Register a user first
    let register_payload = json!({
        "username": "bob_test",
        "password": "correctpassword",
        "role": "vendor"
    });

    let req = test::TestRequest::post()
        .uri("/register")
        .set_form(&register_payload)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 201);

    // Test 1: Login with non-existent username
    let login_payload = json!({
        "username": "nonexistent_user",
        "password": "anypassword"
    });

    let req = test::TestRequest::post()
        .uri("/login")
        .set_form(&login_payload)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status(),
        401,
        "Should return 401 for non-existent user"
    );

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert!(body["error"]
        .as_str()
        .expect("Error field should be a string")
        .contains("Invalid credentials"));

    // Test 2: Login with wrong password
    let login_payload = json!({
        "username": "bob_test",
        "password": "wrongpassword"
    });

    let req = test::TestRequest::post()
        .uri("/login")
        .set_form(&login_payload)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 401, "Should return 401 for wrong password");

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert!(body["error"]
        .as_str()
        .expect("Error field should be a string")
        .contains("Invalid credentials"));

    Ok(())
}

/// Test 3: Whoami without authentication
///
/// # Test Coverage
/// - Access whoami endpoint without session
/// - Verify 401 Unauthorized response
#[actix_web::test]
async fn test_whoami_without_auth() -> Result<(), Box<dyn std::error::Error>> {
    let pool = create_pool(":memory:", "test_encryption_key_32_bytes!!")?;

    // Run migrations
    {
        use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};
        const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations");
        let mut conn = pool.get()?;
        conn.run_pending_migrations(MIGRATIONS)
            .expect("Failed to run migrations");
    }

    let app = test::init_service(create_test_app(pool)).await;

    // Access whoami without session cookie
    let req = test::TestRequest::get().uri("/whoami").to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status(),
        401,
        "Should return 401 when not authenticated"
    );

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert!(body["error"]
        .as_str()
        .expect("Error field should be a string")
        .contains("Not authenticated"));

    Ok(())
}

/// Test 4: Duplicate username registration
///
/// # Test Coverage
/// - Register user with unique username (succeeds)
/// - Attempt to register same username again (fails with 409 Conflict)
#[actix_web::test]
async fn test_duplicate_username() -> Result<(), Box<dyn std::error::Error>> {
    let pool = create_pool(":memory:", "test_encryption_key_32_bytes!!")?;

    // Run migrations
    {
        use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};
        const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations");
        let mut conn = pool.get()?;
        conn.run_pending_migrations(MIGRATIONS)
            .expect("Failed to run migrations");
    }

    let app = test::init_service(create_test_app(pool)).await;

    // Register first user
    let register_payload = json!({
        "username": "charlie_test",
        "password": "password123",
        "role": "buyer"
    });

    let req = test::TestRequest::post()
        .uri("/register")
        .set_form(&register_payload)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 201, "First registration should succeed");

    // Attempt to register with same username
    let req = test::TestRequest::post()
        .uri("/register")
        .set_form(&register_payload)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status(),
        409,
        "Duplicate username should return 409 Conflict"
    );

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert!(body["error"]
        .as_str()
        .expect("Error field should be a string")
        .contains("Username already taken"));

    Ok(())
}

/// Test 5: Input validation
///
/// # Test Coverage
/// - Username too short (min 3 chars)
/// - Password too short (min 8 chars)
/// - Verify 400 Bad Request response
#[actix_web::test]
async fn test_input_validation() -> Result<(), Box<dyn std::error::Error>> {
    let pool = create_pool(":memory:", "test_encryption_key_32_bytes!!")?;

    // Run migrations
    {
        use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};
        const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations");
        let mut conn = pool.get()?;
        conn.run_pending_migrations(MIGRATIONS)
            .expect("Failed to run migrations");
    }

    let app = test::init_service(create_test_app(pool)).await;

    // Test 1: Username too short
    let register_payload = json!({
        "username": "ab", // Only 2 chars
        "password": "validpassword123",
        "role": "buyer"
    });

    let req = test::TestRequest::post()
        .uri("/register")
        .set_form(&register_payload)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status(),
        400,
        "Should return 400 for username too short"
    );

    // Test 2: Password too short
    let register_payload = json!({
        "username": "validuser",
        "password": "short", // Only 5 chars
        "role": "buyer"
    });

    let req = test::TestRequest::post()
        .uri("/register")
        .set_form(&register_payload)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status(),
        400,
        "Should return 400 for password too short"
    );

    Ok(())
}
