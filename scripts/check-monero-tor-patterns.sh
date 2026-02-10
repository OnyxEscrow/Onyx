#!/bin/bash

# Script: check-monero-tor-patterns.sh
# Description: Détecte une liste complète de motifs de sécurité spécifiques à Monero et Tor.

# --- Couleurs ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
GRAY='\033[0;90m'
NC='\033[0m'

# --- Paramètres ---
VERBOSE=false
SCAN_PATH="."

if [ "$1" == "-v" ]; then
    VERBOSE=true
    shift
fi
if [ -n "$1" ]; then
    SCAN_PATH=$1
fi

# --- Définition des motifs de détection ---
declare -A PATTERNS

# Patterns Monero
PATTERNS["Monero: RPC Exposé Publiquement"]='--rpc-bind-ip 0\\.0\\.0\\.0|0\\.0\\.0\\.0:18082'
PATTERNS["Monero: Credentials Hardcodés"]='wallet-password.*=.*["\']|rpc-password.*=.*["\']'
PATTERNS["Monero: View/Spend Keys Loggés"]='log.*view_key|log.*spend_key|println.*view_key|println.*spend_key'
PATTERNS["Monero: Multisig Info Non Sécurisé"]='multisig_info.*println|multisig_info.*log'

# Patterns Tor
PATTERNS["Tor: Connexions Directes"]='reqwest::get\(|TcpStream::connect'
PATTERNS["Tor: Adresses .onion Loggées"]='log.*\.onion|println.*\.onion|tracing.*\.onion'
PATTERNS["Tor: IPs Réelles Loggées"]='log.*[0-9]{1,3}\\\.[0-9]{1,3}|println.*[0-9]{1,3}\\\.[0-9]{1,3}'
PATTERNS["Tor: User-Agent Identifiant"]='User-Agent.*Monero|User-Agent.*Marketplace'
PATTERNS["Tor: Bypass"]='bypass.*tor|skip.*tor|disable.*tor'

# Patterns de sécurité générale
PATTERNS["Security: Random Faible"]='rand::|random\(\)'
PATTERNS["Security: Secrets en Mémoire"]='String::from.*password|String::from.*secret'

# --- Initialisation ---
echo -e "${CYAN}Monero/Tor Patterns Detection${NC}"
echo -e "${CYAN}==============================${NC}"
echo

declare -A issues_by_category
all_issues=()
total_issues=0

# --- Scan des fichiers ---
echo -e "${YELLOW}Scanning Rust files for Monero/Tor patterns...${NC}"
echo

for category in "${!PATTERNS[@]}"; do
    pattern_group=${PATTERNS[$category]}
    grep_results=$(grep -r -n -E --include="*.rs" --exclude-dir={target,.git} "$pattern_group" "$SCAN_PATH" || true)

    if [ -n "$grep_results" ]; then
        while IFS= read -r line; do
            if [[ "$line" =~ ([^:]+):([0-9]+):(.*) ]]; then
                file="${BASH_REMATCH[1]}"
                line_num="${BASH_REMATCH[2]}"
                content="${BASH_REMATCH[3]}"
                trimmed_content=$(echo "$content" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')

                ((total_issues++))
                issues_by_category[$category]=$((issues_by_category[$category]+1))
                all_issues+=("$file:$line_num:$category:$trimmed_content")

                if [ "$VERBOSE" = true ]; then
                    echo -e "${RED}❌ Issue Found: $category${NC}"
                    echo -e "   ${GRAY}${file}:${line_num}${NC}"
                    echo -e "   ${GRAY}$trimmed_content${NC}"
                    echo
                fi
            fi
        done <<< "$grep_results"
    fi
done

# --- Affichage du rapport ---
echo -e "${CYAN}Monero/Tor Security Report${NC}"
echo -e "${CYAN}===========================${NC}"
echo

if [ $total_issues -eq 0 ]; then
    echo -e "${GREEN}✅ No Monero/Tor security issues detected!${NC}"
    echo
    exit 0
fi

echo -e "${RED}❌ Monero/Tor security issues detected: $total_issues issues${NC}"
echo

# Rapport par catégorie
for category in "${!issues_by_category[@]}"; do
    count=${issues_by_category[$category]}
    if [ $count -gt 0 ]; then
        echo -e "${RED}$category: $count issues${NC}"
        
        issues_in_category=()
        for issue in "${all_issues[@]}"; do
            if [[ "$issue" == *":$category:"* ]]; then
                issues_in_category+=("$issue")
            fi
done
        
        for issue in "${issues_in_category[@]:0:3}"; do
            IFS=':' read -r file line_num _ content <<< "$issue"
            echo -e "  ${GRAY}$file:$line_num - $content${NC}"
done

        if [ $count -gt 3 ]; then
            echo -e "  ${GRAY}... and $((count - 3)) more${NC}"
        fi
        echo
    fi
done

# Recommandations
echo -e "${YELLOW}Recommendations:${NC}"
echo -e "  1. Use localhost-only RPC binding (127.0.0.1)"
echo -e "  2. Never log view/spend keys or .onion addresses"
echo -e "  3. Use SOCKS5 proxy for all external connections"
echo -e "  4. Use cryptographically secure random number generation"
echo

echo -e "${RED}❌ COMMIT BLOCKED - Fix Monero/Tor security issues first${NC}"
exit 1
