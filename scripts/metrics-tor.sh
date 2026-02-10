#!/bin/bash

# Script: metrics-tor.sh
# Description: Collecte et affiche les métriques spécifiques à Tor.

# --- Couleurs ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'

# --- Initialisation ---
if [ ! -f ".cursorrules" ]; then
    echo -e "${RED}ERREUR: Exécutez ce script depuis la racine du projet.${NC}"
    exit 1
fi

metrics_dir="docs/metrics"
mkdir -p "$metrics_dir"

current_date=$(date +"%Y-%m-%d")
current_timestamp=$(date +"%Y-%m-%d %H:%M:%S")
output_file="$metrics_dir/tor-$current_date.json"

echo -e "${CYAN}Collecte des métriques Tor...${NC}"

# --- Collecte des données ---

# Test de connectivité Tor
response=$(curl --silent --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip --connect-timeout 10)
tor_connected=$(echo "$response" | jq -r '.IsTor')
tor_exit_node=$(echo "$response" | jq -r '.IP // "N/A"')

# Références .onion
onion_in_logs=$(grep -r -h --include="*.log" "\\.onion" logs/ 2>/dev/null | wc -l)
onion_in_code=$(grep -r -h --include="*.rs" "\\.onion" src/ | wc -l)

# Fonctions liées à Tor
tor_functions=$(grep -r -h -E "socks5|proxy.*tor|via_tor" src/ | wc -l)

# Exposition du RPC
rpc_exposed=$(netstat -an | grep "LISTEN" | grep -q "0\\.0\\.0\\.0:18082" && echo "true" || echo "false")

# Reality Checks Tor
tor_reality_checks=$(find docs/reality-checks -name "tor-*.md" 2>/dev/null | wc -l)

# Fonctions réseau
network_functions=$(grep -r -h -E "reqwest::|curl|http://|https://" src/ | wc -l)
functions_without_tor_check=$((network_functions - tor_reality_checks))

# Violations de sécurité
violation_patterns="0\\.0\\.0\\.0:18082|log.*\\.onion|log.*view_key|log.*spend_key|log.*password"
security_violations=$(grep -r -h -E "$violation_patterns" src/ logs/ 2>/dev/null | wc -l)

# Statut des démons
tor_daemon_running=$(pgrep -x "tor" > /dev/null && echo "true" || echo "false")
monero_rpc_running=$(curl --silent -X POST http://127.0.0.1:18082/json_rpc -d '{}' > /dev/null && echo "true" || echo "false")

# Calcul de la couverture Tor
tor_coverage=0
if [ $network_functions -gt 0 ]; then
    tor_coverage=$(awk -v checks="$tor_reality_checks" -v net="$network_functions" 'BEGIN { printf "%.1f", (checks/net)*100 }')
fi

# --- Sauvegarde en JSON ---
cat << EOF > "$output_file"
{
  "date": "$current_date",
  "timestamp": "$current_timestamp",
  "tor_connected": $tor_connected,
  "tor_exit_node": "$tor_exit_node",
  "tor_daemon_running": $tor_daemon_running,
  "onion_refs_in_logs": $onion_in_logs,
  "onion_refs_in_code": $onion_in_code,
  "tor_functions": $tor_functions,
  "network_functions": $network_functions,
  "functions_without_tor_check": $functions_without_tor_check,
  "rpc_exposed_publicly": $rpc_exposed,
  "monero_rpc_running": $monero_rpc_running,
  "tor_reality_checks": $tor_reality_checks,
  "security_violations": $security_violations,
  "tor_coverage": $tor_coverage
}
EOF

echo -e "${GREEN}Métriques Tor sauvegardées.${NC}"
echo

# --- Affichage du résumé ---
echo -e "${CYAN}Résumé:${NC}"
[ "$tor_connected" = "true" ] && echo -e "  ${GREEN}Connexion Tor: ✓${NC}" || echo -e "  ${RED}Connexion Tor: ✗${NC}"
echo -e "  ${WHITE}Nœud de sortie: $tor_exit_node${NC}"
[ "$tor_daemon_running" = "true" ] && echo -e "  ${GREEN}Démon Tor: ✓${NC}" || echo -e "  ${RED}Démon Tor: ✗${NC}"
[ $onion_in_logs -eq 0 ] && echo -e "  ${GREEN}.onion dans les logs: $onion_in_logs ✅${NC}" || echo -e "  ${RED}.onion dans les logs: $onion_in_logs ⚠️${NC}"
[ "$rpc_exposed" = "false" ] && echo -e "  ${GREEN}RPC Exposé: ✅ NON${NC}" || echo -e "  ${RED}RPC Exposé: ⚠️ OUI${NC}"
echo -e "  ${WHITE}Fonctions Réseau: $network_functions${NC}"
echo -e "  ${WHITE}Reality Checks Tor: $tor_reality_checks${NC}"

color=$RED
if (( $(echo "$tor_coverage >= 80" | bc -l) )); then color=$GREEN;
elif (( $(echo "$tor_coverage >= 50" | bc -l) )); then color=$YELLOW; fi
echo -e "  ${color}Couverture Tor: $tor_coverage%${NC}"
echo -e "  ${WHITE}Violations de sécurité: $security_violations${NC}"

echo
echo -e "${CYAN}Fichier sauvegardé: $output_file${NC}"
