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
    // NEXUS Branding
    docExpansion: "list",
    defaultModelsExpandDepth: 1,
    persistAuthorization: true,
    filter: true,
    tryItOutEnabled: true
  });
};
