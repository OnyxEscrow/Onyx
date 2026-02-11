//! API Documentation Handler
//!
//! Serves Swagger UI and OpenAPI specification for Onyx EaaS API.
//! Provides interactive API documentation at /api/docs.

use actix_web::{get, HttpResponse, Responder};

/// Serve OpenAPI specification (YAML)
///
/// GET /api/docs/openapi.yaml
#[get("/docs/openapi.yaml")]
pub async fn serve_openapi_spec() -> impl Responder {
    const OPENAPI_SPEC: &str = include_str!("../../../docs/api/openapi.yaml");
    HttpResponse::Ok()
        .content_type("application/yaml")
        .body(OPENAPI_SPEC)
}

/// Serve OpenAPI specification (JSON)
///
/// GET /api/docs/openapi.json
#[get("/docs/openapi.json")]
pub async fn serve_openapi_spec_json() -> impl Responder {
    const OPENAPI_SPEC: &str = include_str!("../../../docs/api/openapi.yaml");

    // Parse YAML and convert to JSON
    match serde_yaml::from_str::<serde_json::Value>(OPENAPI_SPEC) {
        Ok(spec) => HttpResponse::Ok()
            .content_type("application/json")
            .json(spec),
        Err(e) => {
            HttpResponse::InternalServerError().body(format!("Failed to parse OpenAPI spec: {e}"))
        }
    }
}

/// Redirect /api/docs to Swagger UI
///
/// GET /api/docs
#[get("/docs")]
pub async fn redirect_to_swagger() -> impl Responder {
    HttpResponse::Found()
        .append_header(("Location", "/api/docs/swagger"))
        .finish()
}

/// Serve Swagger UI
///
/// GET /api/docs/swagger
#[get("/docs/swagger")]
pub async fn serve_swagger_ui() -> impl Responder {
    const SWAGGER_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Onyx API Documentation</title>
    <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5.11.0/swagger-ui.css">
    <style>
        body {
            margin: 0;
            padding: 0;
            background: #0a0a0a;
        }
        .swagger-ui {
            max-width: 1400px;
            margin: 0 auto;
        }
        /* Onyx brand colors */
        .swagger-ui .topbar {
            background-color: #0a0a0a;
            border-bottom: 1px solid #D4AF37;
        }
        .swagger-ui .topbar .download-url-wrapper .select-label {
            color: #D4AF37;
        }
        .swagger-ui .info .title {
            color: #D4AF37;
        }
        .swagger-ui .info .title small.version-stamp {
            background-color: #D4AF37;
        }
        .swagger-ui .opblock.opblock-post {
            border-color: #D4AF37;
            background: rgba(212, 175, 55, 0.1);
        }
        .swagger-ui .opblock.opblock-post .opblock-summary-method {
            background: #D4AF37;
        }
        .swagger-ui .opblock.opblock-get {
            border-color: #61affe;
            background: rgba(97, 175, 254, 0.1);
        }
        .swagger-ui .opblock.opblock-delete {
            border-color: #f93e3e;
            background: rgba(249, 62, 62, 0.1);
        }
        .swagger-ui .opblock.opblock-patch {
            border-color: #50e3c2;
            background: rgba(80, 227, 194, 0.1);
        }
        .swagger-ui .btn.execute {
            background-color: #D4AF37;
            border-color: #D4AF37;
        }
        .swagger-ui .btn.execute:hover {
            background-color: #b8962e;
        }
        .swagger-ui .scheme-container {
            background: #1a1a1a;
            box-shadow: none;
        }
        /* Dark mode adjustments */
        .swagger-ui,
        .swagger-ui .opblock .opblock-summary-description,
        .swagger-ui .opblock-description-wrapper p,
        .swagger-ui .opblock-external-docs-wrapper p,
        .swagger-ui .response-col_description__inner p,
        .swagger-ui table thead tr th,
        .swagger-ui table thead tr td,
        .swagger-ui .parameter__name,
        .swagger-ui .parameter__type,
        .swagger-ui .response-col_status,
        .swagger-ui .response-col_links,
        .swagger-ui .info .title,
        .swagger-ui .info li,
        .swagger-ui .info p,
        .swagger-ui .info table,
        .swagger-ui .markdown p,
        .swagger-ui .markdown li {
            color: #e0e0e0;
        }
        .swagger-ui .opblock-tag {
            color: #D4AF37;
            border-bottom: 1px solid #333;
        }
        .swagger-ui section.models {
            border: 1px solid #333;
        }
        .swagger-ui section.models h4 {
            color: #D4AF37;
        }
        .swagger-ui .model-title {
            color: #D4AF37;
        }
        .swagger-ui .model {
            color: #e0e0e0;
        }
        .swagger-ui .prop-type {
            color: #61affe;
        }
        /* Header styling */
        .onyx-header {
            background: linear-gradient(135deg, #0a0a0a 0%, #1a1a1a 100%);
            padding: 20px;
            text-align: center;
            border-bottom: 2px solid #D4AF37;
        }
        .onyx-header h1 {
            color: #D4AF37;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            font-size: 2.5em;
            margin: 0;
            letter-spacing: 3px;
        }
        .onyx-header p {
            color: #888;
            margin: 10px 0 0 0;
            font-size: 1.1em;
        }
        .onyx-header .badge {
            display: inline-block;
            background: #D4AF37;
            color: #0a0a0a;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 0.8em;
            margin-left: 10px;
            font-weight: bold;
        }
    </style>
</head>
<body>
    <div class="onyx-header">
        <h1>Onyx <span class="badge">EaaS</span></h1>
        <p>Non-Custodial Monero Escrow API</p>
    </div>
    <div id="swagger-ui"></div>
    <script src="https://unpkg.com/swagger-ui-dist@5.11.0/swagger-ui-bundle.js"></script>
    <script src="https://unpkg.com/swagger-ui-dist@5.11.0/swagger-ui-standalone-preset.js"></script>
    <script>
        window.onload = function() {
            window.ui = SwaggerUIBundle({
                url: "/api/docs/openapi.yaml",
                dom_id: '#swagger-ui',
                deepLinking: true,
                presets: [
                    SwaggerUIBundle.presets.apis,
                    SwaggerUIStandalonePreset
                ],
                plugins: [
                    SwaggerUIBundle.plugins.DownloadUrl
                ],
                layout: "StandaloneLayout",
                tryItOutEnabled: true,
                persistAuthorization: true,
                displayRequestDuration: true,
                filter: true,
                showExtensions: true,
                showCommonExtensions: true,
                defaultModelsExpandDepth: 2,
                defaultModelExpandDepth: 2,
                docExpansion: "list",
                syntaxHighlight: {
                    activate: true,
                    theme: "monokai"
                },
                requestInterceptor: (req) => {
                    // Add timestamp to requests for debugging
                    console.log('[Onyx API]', new Date().toISOString(), req.method, req.url);
                    return req;
                },
                responseInterceptor: (res) => {
                    // Log rate limit headers
                    if (res.headers && res.headers['x-ratelimit-remaining']) {
                        console.log('[Onyx API] Rate limit remaining:', res.headers['x-ratelimit-remaining']);
                    }
                    return res;
                }
            });
        };
    </script>
</body>
</html>"#;

    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(SWAGGER_HTML)
}

/// Serve ReDoc UI (alternative documentation)
///
/// GET /api/docs/redoc
#[get("/docs/redoc")]
pub async fn serve_redoc_ui() -> impl Responder {
    const REDOC_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Onyx API Documentation - ReDoc</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        body {
            margin: 0;
            padding: 0;
        }
    </style>
</head>
<body>
    <redoc spec-url="/api/docs/openapi.yaml" hide-hostname="true"></redoc>
    <script src="https://cdn.redoc.ly/redoc/latest/bundles/redoc.standalone.js"></script>
</body>
</html>"#;

    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(REDOC_HTML)
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{test, App};

    #[actix_web::test]
    async fn test_openapi_spec_served() {
        let app = test::init_service(App::new().service(serve_openapi_spec)).await;

        let req = test::TestRequest::get()
            .uri("/docs/openapi.yaml")
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert!(resp.status().is_success());
        assert_eq!(
            resp.headers().get("content-type").unwrap(),
            "application/yaml"
        );
    }

    #[actix_web::test]
    async fn test_swagger_ui_served() {
        let app = test::init_service(App::new().service(serve_swagger_ui)).await;

        let req = test::TestRequest::get().uri("/docs/swagger").to_request();
        let resp = test::call_service(&app, req).await;

        assert!(resp.status().is_success());
        assert!(resp
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap()
            .contains("text/html"));
    }

    #[actix_web::test]
    async fn test_redoc_ui_served() {
        let app = test::init_service(App::new().service(serve_redoc_ui)).await;

        let req = test::TestRequest::get().uri("/docs/redoc").to_request();
        let resp = test::call_service(&app, req).await;

        assert!(resp.status().is_success());
        assert!(resp
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap()
            .contains("text/html"));
    }

    #[actix_web::test]
    async fn test_docs_redirect() {
        let app = test::init_service(App::new().service(redirect_to_swagger)).await;

        let req = test::TestRequest::get().uri("/docs").to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), actix_web::http::StatusCode::FOUND);
        assert_eq!(resp.headers().get("location").unwrap(), "/api/docs/swagger");
    }
}
