
#[cfg(test)]
mod tests {
    use tera::{Context, Tera};
    use serde::Serialize;

    #[derive(Debug, Serialize)]
    pub struct ListingForTemplate {
        pub id: String,
        pub title: String,
        pub description: String,
        pub price: String,
        pub vendor: String,
        pub image_cid: Option<String>,
        pub category: String,
        pub rating: f32,
    }

    #[test]
    fn test_render_listings() {
        let tera = Tera::new("../templates/**/*.html").unwrap();
        let mut ctx = Context::new();
        
        ctx.insert("logged_in", &true);
        ctx.insert("role", "buyer");
        ctx.insert("username", "testuser");
        ctx.insert("csrf_token", "testtoken");

        let listings = vec![
            ListingForTemplate {
                id: "test-id".to_string(),
                title: "Test Listing".to_string(),
                description: "Test Description".to_string(),
                price: "1.0000 XMR".to_string(),
                vendor: "testvendor".to_string(),
                image_cid: Some("QmTest".to_string()),
                category: "Digital".to_string(),
                rating: 4.8,
            }
        ];

        ctx.insert("listings", &listings);

        match tera.render("listings/index.html", &ctx) {
            Ok(_) => println!("Render successful"),
            Err(e) => panic!("Render failed: {}", e),
        }
    }
}
