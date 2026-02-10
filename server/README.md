# Monero Marketplace Server

Backend web service pour le Monero Marketplace. Service HTTP accessible uniquement via Tor hidden service (.onion).

## Architecture

- **Framework**: Actix-web 4.x
- **Runtime**: Tokio async
- **Accès**: Tor hidden service uniquement (.onion)
- **Port**: 8080 (localhost, mappé vers Tor)

## Démarrage Rapide

### 1. Compiler le projet

```bash
cargo build --workspace
```

### 2. Démarrer le serveur (localhost)

```bash
./scripts/start-server.sh
```

Le serveur démarre sur `http://127.0.0.1:8080`

### 3. Tester l'endpoint health

```bash
curl http://127.0.0.1:8080/api/health
```

Réponse attendue:
```json
{
  "status": "ok"
}
```

## Configuration Tor Hidden Service

### Installation et configuration de Tor

```bash
sudo ./scripts/setup-tor.sh
```

Ce script:
1. Installe Tor si nécessaire
2. Configure un hidden service v3
3. Mappe le port 80 (.onion) vers le port 8080 (localhost)
4. Génère votre adresse .onion

### Obtenir votre adresse .onion

```bash
sudo cat /var/lib/tor/monero_marketplace/hostname
```

Exemple de sortie:
```
abc123def456ghi789jkl.onion
```

### Tester l'accès via Tor

1. Démarrer le serveur:
```bash
./scripts/start-server.sh
```

2. Dans un autre terminal, tester via Tor:
```bash
curl --socks5-hostname 127.0.0.1:9050 http://votre-adresse.onion/api/health
```

## Endpoints API

### Version actuelle (v0.1.0 - Milestone 2.1)

| Endpoint | Méthode | Description |
|----------|---------|-------------|
| `/api/health` | GET | Health check du serveur |
| `/` | GET | Informations API |

### Prochainement (Milestone 2.2)

| Endpoint | Méthode | Description |
|----------|---------|-------------|
| `/api/v1/auth/register` | POST | Enregistrement utilisateur |
| `/api/v1/auth/login` | POST | Connexion |
| `/api/v1/auth/logout` | POST | Déconnexion |
| `/api/v1/listings` | GET | Liste des annonces |
| `/api/v1/listings` | POST | Créer une annonce |
| `/api/v1/orders` | GET | Liste des commandes |
| `/api/v1/escrow` | POST | Initier un escrow |

## Développement

### Structure du code

```
server/
├── src/
│   └── main.rs          # Point d'entrée, routes, configuration
├── Cargo.toml           # Dépendances
└── README.md            # Ce fichier
```

### Dépendances

- `actix-web` - Framework web async
- `actix-session` - Gestion des sessions
- `actix-web-actors` - Support WebSocket
- `tokio` - Runtime async
- `serde` / `serde_json` - Sérialisation JSON

### Ajouter une nouvelle route

1. Définir le handler dans `src/main.rs`:
```rust
async fn my_handler() -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({
        "message": "Hello"
    }))
}
```

2. Enregistrer la route dans `configure_routes()`:
```rust
cfg.route("/api/my-endpoint", web::get().to(my_handler));
```

## Sécurité

### Bonnes Pratiques

1. **Tor uniquement**: Ne JAMAIS exposer le serveur sur clearnet
2. **Pas de logs sensibles**: Aucune information utilisateur dans les logs
3. **Rate limiting**: Implémenter dans Milestone 2.2
4. **CSRF protection**: Implémenter dans Milestone 2.2
5. **Sessions sécurisées**: Cookie-based avec encryption

### Configuration de production

```rust
// TODO: Milestone 2.2
// - Activer HTTPS (même sur .onion)
// - Configurer rate limiting
// - Activer CSRF protection
// - Chiffrer les cookies de session
```

## Tests

### Tests unitaires

```bash
cargo test -p server
```

### Test d'intégration (serveur + sanity check)

```bash
# Terminal 1: Démarrer le serveur
./scripts/start-server.sh

# Terminal 2: Tester
curl http://127.0.0.1:8080/api/health
```

## Logs

Le serveur utilise `tracing` pour les logs structurés.

### Niveau de log par défaut
```
INFO
```

### Changer le niveau de log
```bash
RUST_LOG=debug cargo run --bin server
```

### Niveaux disponibles
- `error` - Erreurs critiques seulement
- `warn` - Avertissements + erreurs
- `info` - Informations générales (défaut)
- `debug` - Détails de débogage
- `trace` - Tout, très verbeux

## Roadmap

### Phase 2 - Backend Web Service

- [x] **Milestone 2.1** - Tor Hidden Service (Semaines 7-8) ✅ COMPLÉTÉ
  - [x] Serveur HTTP basique avec Actix-web
  - [x] Endpoint `/api/health`
  - [x] Script de configuration Tor
  - [x] Tests d'accessibilité .onion
  - **Adresse .onion**: `bikbopwe33kt6a3hva4zjmj7mer5acvxrmvrky2uqsr6xkzdr676lead.onion`
  - **Tests réussis**: Accessibilité localhost et Tor SOCKS5 validés

- [ ] **Milestone 2.2** - API REST Core (Semaines 9-11)
  - [ ] Routes d'authentification
  - [ ] Routes de listings (CRUD)
  - [ ] Routes d'orders
  - [ ] Routes d'escrow
  - [ ] Middleware (rate limiting, CSRF, sessions)

- [ ] **Milestone 2.3** - Database (Semaines 12-14)
  - [ ] Schema SQLite + sqlcipher
  - [ ] Diesel ORM
  - [ ] Migrations
  - [ ] Chiffrement des données sensibles

## Troubleshooting

### Le serveur ne démarre pas

1. Vérifier que le port 8080 n'est pas déjà utilisé:
```bash
lsof -i :8080
```

2. Vérifier les logs:
```bash
RUST_LOG=debug cargo run --bin server
```

### Tor ne se connecte pas

1. Vérifier le statut de Tor:
```bash
sudo systemctl status tor
```

2. Consulter les logs Tor:
```bash
sudo tail -f /var/log/tor/notices.log
```

3. Redémarrer Tor:
```bash
sudo systemctl restart tor
```

### Erreur de compilation

```bash
# Nettoyer et rebuilder
cargo clean
cargo build --workspace
```

## Liens Utiles

- [Documentation Actix-web](https://actix.rs/docs/)
- [Documentation Tor](https://2019.www.torproject.org/docs/tor-manual.html.en)
- [PLAN-COMPLET.md](../PLAN-COMPLET.md) - Roadmap complète du projet
