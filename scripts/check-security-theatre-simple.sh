#!/bin/bash

# Script: check-security-theatre-simple.sh
# Description: Détecte les motifs de "security theatre" de base dans le code Rust.
# Usage: ./scripts/check-security-theatre-simple.sh [-v] [/path/to/scan]

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
IGNORE_FILE=".security-theatre-ignore"

if [ "$1" == "-v" ]; then
    VERBOSE=true
    shift
fi
if [ -n "$1" ]; then
    SCAN_PATH=$1
fi

# --- Définition des motifs de détection (tous regroupés) ---
ALL_PATTERNS=(
    '\.unwrap\s*\(\s*\)' '\.expect\s*\(\s*""\s*\)' 'println!' 'print!' 'eprintln!' 'eprint!' 'dbg!' # Patterns interdits
    '//.*Placeholder' '//.*TODO' '//.*FIXME' '//.*XXX' '//.*HACK' '//.*TEMP' '//.*Temporary' # Placeholders
    'unimplemented!' 'todo!' 'panic!' # Code mort
    'should.*work' 'assume' 'hope' 'guess' # Suppositions
    'password.*=' 'secret.*=' 'key.*=' 'token.*=' 'api_key.*=' 'private_key.*=' # Credentials
)

# Concaténer les motifs pour grep
GREP_PATTERN=$(IFS='|'; echo "${ALL_PATTERNS[*]}")

# --- Initialisation ---
echo -e "${CYAN}Security Theatre Detection (Simple)${NC}"
echo -e "${CYAN}====================================${NC}"
echo

all_issues=()
total_issues=0

# --- Chargement des exceptions ---
exceptions=()
if [ -f "$IGNORE_FILE" ]; then
    while IFS= read -r line || [[ -n "$line" ]]; do
        if [[ ! "$line" =~ ^\s*# ]] && [[ -n "$line" ]]; then
            exceptions+=("$line")
        fi
    done < "$IGNORE_FILE"
fi

# --- Fonction de vérification des exceptions ---
is_ignored() {
    local file_path=$1
    local line_content=$2
    for exc in "${exceptions[@]}"; do
        if [[ "$exc" =~ (.+):(.+) ]]; then
            local file_pattern="${BASH_REMATCH[1]}"
            local line_pattern="${BASH_REMATCH[2]}"
            if [[ "$file_path" == $file_pattern && "$line_content" =~ $line_pattern ]]; then
                return 0 # true
            fi
        fi
    done
    return 1 # false
}

# --- Scan des fichiers ---
rust_files=$(find "$SCAN_PATH" -name "*.rs" -not -path "*/target/*" -not -path "*/.git/*")
file_count=$(echo "$rust_files" | wc -w)
echo -e "${YELLOW}Scanning $file_count Rust files...${NC}"
echo

grep_results=$(grep -r -n -E --include="*.rs" --exclude-dir={target,.git} "$GREP_PATTERN" "$SCAN_PATH" || true)

if [ -n "$grep_results" ]; then
    while IFS= read -r line; do
        if [[ "$line" =~ ([^:]+):([0-9]+):(.*) ]]; then
            file="${BASH_REMATCH[1]}"
            line_num="${BASH_REMATCH[2]}"
            content="${BASH_REMATCH[3]}"
            trimmed_content=$(echo "$content" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')

            if ! is_ignored "$file" "$trimmed_content"; then
                ((total_issues++))
                all_issues+=("$file:$line_num:$trimmed_content")

                if [ "$VERBOSE" = true ]; then
                    echo -e "${RED}❌ Security theatre detected${NC}"
                    echo -e "   ${GRAY}${file}:${line_num}${NC}"
                    echo -e "   ${GRAY}$trimmed_content${NC}"
                    echo
                fi
            fi
        fi
    done <<< "$grep_results"
fi

# --- Affichage du rapport ---
echo -e "${CYAN}Security Theatre Report${NC}"
echo -e "${CYAN}=========================${NC}"
echo

if [ $total_issues -eq 0 ]; then
    echo -e "${GREEN}✅ No security theatre detected!${NC}"
    echo
    exit 0
fi

echo -e "${RED}❌ Security theatre detected: $total_issues issues${NC}"
echo

# Top 10 des issues
echo -e "${RED}Top Issues:${NC}"
for issue in "${all_issues[@]:0:10}"; do
    IFS=':' read -r file line_num content <<< "$issue"
    echo -e "  ${RED}$file:$line_num${NC}"
    echo -e "    ${GRAY}$content${NC}"
done
echo

# Recommandations
echo -e "${YELLOW}Recommendations:${NC}"
echo -e "  1. Replace .unwrap() with proper error handling."
echo -e "  2. Remove placeholder comments and implement real code."
echo

echo -e "${RED}❌ COMMIT BLOCKED - Fix security theatre issues first${NC}"
exit 1
