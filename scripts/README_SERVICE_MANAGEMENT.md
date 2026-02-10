# NEXUS Service Management Scripts

Scripts pour gérer automatiquement tous les services nécessaires au fonctionnement de NEXUS Marketplace.

## Scripts Disponibles

### 1. `start-all-services.sh` - Démarrage complet

Démarre automatiquement tous les services requis:
- ✅ Tor daemon (hidden service)
- ✅ Monero wallet RPC (testnet, port 18083)
- ✅ IPFS daemon (reputation storage, port 5001)
- ✅ NEXUS server (avec tous les monitors en arrière-plan)

**Usage:**
```bash
./scripts/start-all-services.sh
```

**Ce que fait le script:**
1. Vérifie si Tor est actif, le démarre si nécessaire
2. Démarre Monero wallet RPC sur port 18083
3. Démarre IPFS daemon sur port 5001
4. Vérifie/applique les migrations de base de données
5. Compile le serveur si nécessaire
6. Démarre le serveur NEXUS sur http://127.0.0.1:8080
7. Affiche un résumé de tous les services

**Services en arrière-plan automatiques:**
- **TimeoutMonitor**: Surveille les timeouts d'escrow
- **BlockchainMonitor**: Polling de la blockchain toutes les 30s
- **MultisigAutoCoordinator**: Coordination multisig automatique (interval 5s)
- **WasmMultisigStore**: Coordination multisig WASM

**Logs:**
- Server: `server.log`
- Monero wallet RPC: `.monero-wallets/wallet-rpc.log`
- IPFS daemon: `ipfs-daemon.log`

### 2. `stop-all-services.sh` - Arrêt complet

Arrête proprement tous les services NEXUS.

**Usage:**
```bash
# Arrêter tous les services (sauf Tor)
./scripts/stop-all-services.sh

# Arrêter tous les services Y COMPRIS Tor
./scripts/stop-all-services.sh --stop-tor

# Arrêter et nettoyer tous les logs
./scripts/stop-all-services.sh --clean-logs
```

**Options:**
- `--stop-tor`: Arrête aussi le daemon Tor (service système)
- `--clean-logs`: Supprime tous les fichiers de logs

**Méthode d'arrêt:**
1. SIGTERM (graceful shutdown)
2. Attente de 10 secondes
3. SIGKILL (force) si nécessaire

### 3. `status-all-services.sh` - Vérification du statut

Affiche l'état détaillé de tous les services.

**Usage:**
```bash
./scripts/status-all-services.sh
```

**Informations affichées:**
- ✅ Status de chaque service (RUNNING / NOT RUNNING)
- 📊 Version des composants
- 💾 Utilisation CPU/mémoire du serveur
- 🔗 Nombre de connexions actives
- 📝 Taille des logs et erreurs récentes
- 🗄️ État de la base de données et migrations
- 📡 État des services en arrière-plan

**Exemple de sortie:**
```
════════════════════════════════════════════════════════════
   NEXUS MARKETPLACE - SERVICE STATUS
════════════════════════════════════════════════════════════

1. Tor Daemon
   Status: RUNNING
   SOCKS Proxy: 127.0.0.1:9050
   Connectivity: OK

2. Monero Wallet RPC (Testnet)
   Status: RUNNING
   Port: 18083
   Version: 65565
   PID: 12345

3. IPFS Daemon
   Status: RUNNING
   API Port: 5001
   Peers: 13

4. NEXUS Server
   Status: RUNNING
   URL: http://127.0.0.1:8080
   PID: 67890
   CPU: 2.3%
   Memory: 1.5% (85.4 MB)
   Uptime: 02:34:56

5. Background Services
   TimeoutMonitor: STARTED
   BlockchainMonitor: STARTED (30s polling)
   MultisigAutoCoordinator: STARTED (5s polling)

6. Database
   Status: EXISTS
   Size: 388K
   Migrations Applied: 24

════════════════════════════════════════════════════════════
   All services running (4/4) ✅
════════════════════════════════════════════════════════════
```

## Flux de Travail Typique

### Démarrage du développement
```bash
# 1. Vérifier le statut actuel
./scripts/status-all-services.sh

# 2. Démarrer tous les services si nécessaire
./scripts/start-all-services.sh

# 3. Vérifier que tout est OK
./scripts/status-all-services.sh
```

### Arrêt propre
```bash
# Arrêter tous les services
./scripts/stop-all-services.sh

# Ou arrêter avec nettoyage complet
./scripts/stop-all-services.sh --clean-logs
```

### Redémarrage après modification du code
```bash
# 1. Arrêter le serveur uniquement
pkill -9 -f "target/release/server"

# 2. Recompiler
cargo build --release --package server

# 3. Redémarrer tout
./scripts/start-all-services.sh
```

## Dépendances Requises

### Obligatoires
- **Tor**: `sudo apt install tor`
- **Monero CLI**: Télécharger depuis https://www.getmonero.org/downloads/
- **Rust/Cargo**: Pour compiler le serveur
- **Diesel CLI**: `cargo install diesel_cli --no-default-features --features sqlite`

### Optionnelles
- **IPFS**: Télécharger depuis https://docs.ipfs.tech/install/
  - Si absent, le script continue sans IPFS (reputation export désactivé)
- **jq**: `sudo apt install jq` (pour parsing JSON dans status script)

## Fichiers Créés par les Scripts

```
NEXUS/
├── .server.pid                    # PID du serveur NEXUS
├── server.log                     # Logs du serveur
├── ipfs-daemon.log                # Logs IPFS (si démarré par script)
├── .ipfs-daemon.pid               # PID IPFS
├── .monero-wallets/
│   ├── wallet-rpc.pid            # PID Monero wallet RPC
│   └── wallet-rpc.log            # Logs Monero wallet RPC
└── marketplace.db                 # Base de données SQLite
```

## Sécurité

**IMPORTANT:**
- Tous les services sont bindés sur **127.0.0.1 uniquement** (localhost)
- Aucun service n'est exposé publiquement
- Tor daemon utilise SOCKS proxy sur 127.0.0.1:9050
- Monero wallet RPC: **--disable-rpc-login** (OK pour testnet local)
- Les clés privées restent dans le navigateur (non-custodial WASM)

**Pour production:**
- Activer authentication sur Monero wallet RPC
- Configurer Tor hidden service
- Activer HTTPS/TLS
- Rate limiting renforcé

## Troubleshooting

### Erreur: "Tor daemon not running"
```bash
sudo systemctl start tor
sudo systemctl enable tor  # Démarrage automatique au boot
```

### Erreur: "monero-wallet-rpc not found"
```bash
# Télécharger Monero CLI
wget https://downloads.getmonero.org/cli/linux64
tar -xvf linux64
sudo cp monero-*/monero-wallet-rpc /usr/local/bin/
```

### Erreur: "Port already in use"
```bash
# Trouver le processus qui utilise le port
lsof -i :8080
lsof -i :18083
lsof -i :5001

# Tuer le processus
kill -9 <PID>

# Ou utiliser le script stop
./scripts/stop-all-services.sh
```

### Erreur: "Database locked"
```bash
# Vérifier les processus qui accèdent à la DB
lsof marketplace.db

# Arrêter tous les services
./scripts/stop-all-services.sh

# Redémarrer proprement
./scripts/start-all-services.sh
```

### Erreur: "Pending migrations"
```bash
# Appliquer les migrations
DATABASE_URL=marketplace.db diesel migration run

# Ou laisser le script le faire automatiquement
./scripts/start-all-services.sh
```

### Logs ne s'affichent pas
```bash
# Suivre les logs en temps réel
tail -f server.log
tail -f .monero-wallets/wallet-rpc.log
tail -f ipfs-daemon.log

# Chercher des erreurs spécifiques
grep -i "error" server.log | tail -n 20
```

## Performances

**Temps de démarrage typiques:**
- Tor daemon: ~2-3 secondes (si déjà installé)
- Monero wallet RPC: ~3-5 secondes
- IPFS daemon: ~5-10 secondes (première fois ~30s)
- NEXUS server: ~2-3 secondes (compilation: ~30-60s)

**Total: ~15 secondes** (avec binaires déjà compilés)

**Utilisation ressources (idle):**
- Tor: ~10MB RAM, <1% CPU
- Monero wallet RPC: ~50-100MB RAM, <1% CPU
- IPFS: ~100-200MB RAM, <5% CPU
- NEXUS server: ~80-150MB RAM, 1-3% CPU

**Total: ~250-460MB RAM, <10% CPU**

## Automatisation au Boot (Optionnel)

Pour démarrer automatiquement NEXUS au démarrage du système:

### Méthode 1: systemd service (recommandé)
```bash
# Créer un service systemd
sudo nano /etc/systemd/system/nexus-marketplace.service
```

Contenu:
```ini
[Unit]
Description=NEXUS Marketplace
After=network.target tor.service

[Service]
Type=forking
User=malix
WorkingDirectory=/home/malix/Desktop/NEXUS
ExecStart=/home/malix/Desktop/NEXUS/scripts/start-all-services.sh
ExecStop=/home/malix/Desktop/NEXUS/scripts/stop-all-services.sh
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Activer:
```bash
sudo systemctl daemon-reload
sudo systemctl enable nexus-marketplace
sudo systemctl start nexus-marketplace
```

### Méthode 2: crontab (simple)
```bash
crontab -e
```

Ajouter:
```
@reboot sleep 30 && /home/malix/Desktop/NEXUS/scripts/start-all-services.sh
```

## Intégration avec Git Hooks

Ajouter un pre-commit hook pour vérifier que les services sont actifs:

```bash
# .git/hooks/pre-commit
#!/bin/bash

if ! curl -s http://127.0.0.1:8080/health &>/dev/null; then
    echo "❌ NEXUS server not running!"
    echo "Start with: ./scripts/start-all-services.sh"
    exit 1
fi

echo "✅ Services running"
```

## Support et Maintenance

**Logs centralisés:**
```bash
# Créer un alias pour voir tous les logs
alias nexus-logs='tail -f server.log .monero-wallets/wallet-rpc.log ipfs-daemon.log'
```

**Health check périodique (cron):**
```bash
# Vérifier toutes les 5 minutes
*/5 * * * * /home/malix/Desktop/NEXUS/scripts/status-all-services.sh > /tmp/nexus-status.log 2>&1
```

**Backup automatique de la DB:**
```bash
# Tous les jours à 2h du matin
0 2 * * * cp /home/malix/Desktop/NEXUS/marketplace.db /home/malix/Desktop/NEXUS/backups/marketplace-$(date +\%Y\%m\%d).db
```

## Références

- **Tor**: https://www.torproject.org/
- **Monero**: https://www.getmonero.org/
- **IPFS**: https://ipfs.tech/
- **NEXUS Documentation**: `DOX/`

---

**Version:** 1.0.0
**Date:** 2025-11-24
**Auteur:** Onyx-Escrow Team
**License:** Proprietary (NEXUS Marketplace)
