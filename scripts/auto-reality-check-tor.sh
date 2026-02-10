#!/bin/bash

# Script: auto-reality-check-tor.sh
# Génère automatiquement un reality check Tor avec tests automatiques.
# Dépendance: jq (pour l'analyse JSON)
# Usage: ./scripts/auto-reality-check-tor.sh <function_name>

# --- Couleurs ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'

# --- Vérification des dépendances ---
if ! command -v jq &> /dev/null;
    then
    echo -e "${RED}ERREUR: 'jq' n'est pas installé. Veuillez l'installer pour continuer (ex: sudo apt-get install jq).${NC}"
    exit 1
fi

# --- Vérification des arguments ---
if [ -z "$1" ]; then
    echo -e "${RED}ERREUR: Nom de la fonction manquant.${NC}"
    echo "Usage: $0 <function_name>"
    exit 1
fi

FunctionName=$1

# --- Vérification du répertoire racine ---
if [ ! -f ".cursorrules" ]; then
    echo -e "${RED}ERREUR: Exécutez ce script depuis la racine du projet.${NC}"
    exit 1
fi

# --- Préparation des fichiers et répertoires ---
reality_checks_dir="docs/reality-checks"
mkdir -p "$reality_checks_dir"

current_date=$(date +"%Y-%m-%d")
current_timestamp=$(date +"%Y-%m-%d %H:%M:%S")
reality_check_file="${reality_checks_dir}/tor-${FunctionName}-${current_date}.md"

echo -e "${CYAN}Génération du Reality Check TOR pour: $FunctionName${NC}"
echo -e "${CYAN}===============================================${NC}"

# ============================================
# TESTS AUTOMATIQUES TOR
# ============================================
echo -e "\n${YELLOW}Exécution des tests automatiques...${NC}"

# --- Variables de résultats ---
tor_daemon_running="false"
tor_daemon_result="NOT Running"
ip_leak_test="false"
ip_leak_result="FAILED - Tor not accessible"
tor_ip="N/A"
monero_rpc_accessible="false"
monero_rpc_result="NOT accessible"
rpc_exposed="false"
port_exposure_result="RPC not running"
logs_clean="true"
logs_audit_result="No log files found"
tor_version="Unknown"

# 1. Test Tor Daemon
echo -e "${WHITE}1. Test Tor Daemon...${NC}"
if pgrep -x "tor" > /dev/null; then
    tor_daemon_running="true"
    tor_daemon_result="Running"
    echo -e "   ${GREEN}Tor Daemon: Running${NC}"
else
    echo -e "   ${RED}Tor Daemon: NOT Running${NC}"
fi

# 2. Test IP Leak
echo -e "${WHITE}2. Test IP Leak...${NC}"
# Assurez-vous que le proxy est correct pour votre configuration
tor_proxy="socks5h://127.0.0.1:9050"
# Le 'h' dans socks5h délègue la résolution DNS au proxy
ip_check_url="https://check.torproject.org/api/ip"
http_status=$(curl --silent --output /dev/null --write-out "%{{http_code}}" --proxy "$tor_proxy" "$ip_check_url" --connect-timeout 10)

if [ "$http_status" -eq 200 ]; then
    response=$(curl --silent --proxy "$tor_proxy" "$ip_check_url")
    is_tor=$(echo "$response" | jq -r '.IsTor')
    tor_ip=$(echo "$response" | jq -r '.IP')
    if [ "$is_tor" == "true" ]; then
        ip_leak_test="true"
        ip_leak_result="Using Tor ($tor_ip)"
        echo -e "   ${GREEN}IP Leak Test: Using Tor ($tor_ip)${NC}"
    else
        ip_leak_result="NOT using Tor ($tor_ip)"
        echo -e "   ${RED}IP Leak Test: NOT using Tor ($tor_ip)${NC}"
    fi
else
    echo -e "   ${RED}IP Leak Test: FAILED - Tor not accessible (HTTP status: $http_status)${NC}"
fi


# 3. Test Monero RPC
echo -e "${WHITE}3. Test Monero RPC...${NC}"
rpc_response=$(curl --silent -X POST http://127.0.0.1:18082/json_rpc -H 'Content-Type: application/json' -d '''{"jsonrpc":"2.0","id":"0","method":"get_version"}''' --connect-timeout 5)
if [[ $rpc_response == *"result"* ]]; then
    monero_rpc_accessible="true"
    monero_rpc_result="Accessible on localhost"
    echo -e "   ${GREEN}Monero RPC: Accessible on localhost${NC}"
else
    echo -e "   ${RED}Monero RPC: NOT accessible${NC}"
fi

# 4. Test Port Exposure
echo -e "${WHITE}4. Test Port Exposure...${NC}"
if netstat -an | grep -q "LISTEN" | grep -q ":18082"; then
    if netstat -an | grep -q "LISTEN" | grep -q "0\.0\.0\.0:18082"; then
        rpc_exposed="true"
        port_exposure_result="RPC exposed publicly (DANGER!)"
        echo -e "   ${RED}Port Exposure: RPC exposed publicly (DANGER!)${NC}"
    elif netstat -an | grep -q "LISTEN" | grep -q "127\.0\.0\.1:18082"; then
        port_exposure_result="RPC isolated on localhost"
        echo -e "   ${GREEN}Port Exposure: RPC isolated on localhost${NC}"
    fi
else
    echo -e "   ${YELLOW}Port Exposure: RPC not running${NC}"
fi

# 5. Test Logs Audit
echo -e "${WHITE}5. Test Logs Audit...${NC}"
sensitive_patterns="\.onion|view_key|spend_key|password|secret"
log_dir="logs"
if [ -d "$log_dir" ]; then
    if grep -rE -q "$sensitive_patterns" "$log_dir"; then
        logs_clean="false"
        found_pattern=$(grep -rE -o "$sensitive_patterns" "$log_dir" | head -n 1)
        logs_audit_result="Sensitive data found ($found_pattern)"
        echo -e "   ${RED}Logs Audit: Sensitive data found ($found_pattern)${NC}"
    else
        logs_audit_result="No sensitive data in logs"
        echo -e "   ${GREEN}Logs Audit: No sensitive data in logs${NC}"
    fi
else
    echo -e "   ${YELLOW}Logs Audit: No log files found${NC}"
fi

# 6. Test Tor Version
echo -e "${WHITE}6. Test Tor Version...${NC}"
if command -v tor &> /dev/null; then
    version_output=$(tor --version)
    if [[ $version_output =~ Tor[[:space:]]version[[:space:]]([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+) ]]; then
        tor_version=${BASH_REMATCH[1]}
        echo -e "   ${GREEN}Tor Version: $tor_version${NC}"
    else
        echo -e "   ${YELLOW}Tor Version: Unknown format${NC}"
    fi
else
    tor_version="Not accessible"
    echo -e "   ${RED}Tor Version: Not accessible${NC}"
fi

# --- Calculer les issues critiques ---
critical_issues=0
if [ "$tor_daemon_running" == "false" ]; then ((critical_issues++)); fi
if [ "$ip_leak_test" == "false" ]; then ((critical_issues++)); fi
if [ "$rpc_exposed" == "true" ]; then ((critical_issues++)); fi
if [ "$logs_clean" == "false" ]; then ((critical_issues++)); fi

auto_tests_passed="false"
if [ $critical_issues -eq 0 ]; then
    auto_tests_passed="true"
fi

# ============================================
# GENERATION DU REALITY CHECK
# ============================================
echo -e "\n${YELLOW}Génération du Reality Check Tor...${NC}"

# --- Metadata JSON ---
metadata_json=$(cat <<EOF
{
  "date": "$current_date",
  "timestamp": "$current_timestamp",
  "function_name": "$FunctionName",
  "tor_daemon": "$tor_daemon_result",
  "ip_leak_test": "$ip_leak_result",
  "monero_rpc": "$monero_rpc_result",
  "port_exposure": "$port_exposure_result",
  "logs_audit": "$logs_audit_result",
  "tor_version": "$tor_version",
  "auto_tests_passed": $auto_tests_passed,
  "critical_issues": $critical_issues
}
EOF
)

# --- Template Reality Check Tor ---
cat << EOF > "$reality_check_file"
# Reality Check Tor: $FunctionName
**Date:** $current_date  
**Heure:** $current_timestamp  
**Fonction:** $FunctionName
**Threat Level:** HIGH (Network Code)

---

## 🧅 Tests Automatiques
\`\`\`json
$metadata_json
\`\`\`

## 📋 Résultats Tests Automatiques:
- **Tor Daemon:** $tor_daemon_result
- **IP Leak Test:** $ip_leak_result
- **Monero RPC:** $monero_rpc_result
- **Port Exposure:** $port_exposure_result
- **Logs Audit:** $logs_audit_result
- **Tor Version:** $tor_version

**Issues Critiques:** $critical_issues
**Tests Auto Passés:** $(if [ "$auto_tests_passed" == "true" ]; then echo "OUI"; else echo "NON"; fi)

---

## ✅ Tests Manuels OPSEC

### Tests de Fuite
- [ ] **DNS Leak Test**
  - [ ] DNS via Tor uniquement
  - [ ] Pas de requêtes DNS directes
  - [ ] Résolution .onion fonctionnelle

- [ ] **Fingerprinting Test**
  - [ ] Fingerprint anonyme
  - [ ] User-Agent générique
  - [ ] Pas de metadata unique

- [ ] **Hidden Service Test** (si applicable)
  - [ ] Accès .onion fonctionnel
  - [ ] Pas de fallback clearnet
  - [ ] Certificat valide

- [ ] **Traffic Analysis Test**
  - [ ] Pas de patterns temporels
  - [ ] Taille de paquets variable
  - [ ] Pas de corrélation évidente

### Tests de Sécurité
- [ ] **RPC Isolation**
  - [ ] RPC NOT exposed publicly
  - [ ] Bind uniquement sur 127.0.0.1
  - [ ] Pas d'accès depuis l'extérieur

- [ ] **Logs Security**
  - [ ] Pas de .onion dans logs
  - [ ] Pas de credentials dans logs
  - [ ] Logs niveau approprié

- [ ] **Network Security**
  - [ ] Toutes requêtes via Tor
  - [ ] Pas de connexions directes
  - [ ] Timeouts appropriés

---

## Decision Finale

### Status des Tests
- [ ] **APPROUVÉ** - Prêt pour production Tor
- [ ] **CONDITIONNEL** - Améliorations requises
- [ ] **REJETÉ** - Recommencer

### Justification
[Expliquer la décision basée sur les tests]

### Actions Requises (si conditionnel/rejeté)
- [ ] [Action 1]
- [ ] [Action 2]
- [ ] [Action 3]

---

## Notes OPSEC

### Observations
[Notes sur le comportement Tor, anomalies, etc.]

### Recommandations
[Suggestions d'amélioration OPSEC]

### Limitations Identifiées
[Limitations de sécurité connues]

---

## Checklist Finale

- [ ] Tous les tests auto passent
- [ ] Tests manuels complétés
- [ ] Aucune fuite détectée
- [ ] RPC correctement isolé
- [ ] Logs propres
- [ ] Décision prise et justifiée

---

## Validation

**Testé par:** [Nom] **[Signature]**  
**Date de validation:** $current_date  
**Status:** [ ] Valide pour production

**Commentaires finaux:**
[Commentaires sur la validation Tor]
EOF

echo -e "${GREEN}Reality Check TOR généré: $reality_check_file${NC}"

# --- Afficher le résumé ---
echo -e "\n${CYAN}RÉSUMÉ DES TESTS AUTOMATIQUES:${NC}"
echo -e "${CYAN}=============================${NC}"
[ "$tor_daemon_running" == "true" ] && echo -e "${GREEN}Tor Daemon: ✓${NC}" || echo -e "${RED}Tor Daemon: ✗${NC}"
[ "$ip_leak_test" == "true" ] && echo -e "${GREEN}IP Leak Test: ✓${NC}" || echo -e "${RED}IP Leak Test: ✗${NC}"
[ "$monero_rpc_accessible" == "true" ] && echo -e "${GREEN}Monero RPC: ✓${NC}" || echo -e "${RED}Monero RPC: ✗${NC}"
[ "$rpc_exposed" == "false" ] && echo -e "${GREEN}Port Exposure: ✓${NC}" || echo -e "${RED}Port Exposure: ✗${NC}"
[ "$logs_clean" == "true" ] && echo -e "${GREEN}Logs Audit: ✓${NC}" || echo -e "${RED}Logs Audit: ✗${NC}"
echo -e "${WHITE}Tor Version: $tor_version${NC}"

echo # Saut de ligne

if [ $critical_issues -eq 0 ]; then
    echo -e "${GREEN}Issues Critiques: 0${NC}"
    echo -e "${GREEN}Tests Auto Passés: ✅ OUI${NC}"
    echo -e "\n${GREEN}✅ Tests automatiques passés - complétez les tests manuels.${NC}"
    exit 0
else
    echo -e "${RED}Issues Critiques: $critical_issues${NC}"
    echo -e "${RED}Tests Auto Passés: ❌ NON${NC}"
    echo -e "\n${RED}⚠️ ATTENTION: Issues critiques détectées!${NC}"
    echo -e "${YELLOW}Corrigez les problèmes avant de continuer.${NC}"
    exit 1
fi
