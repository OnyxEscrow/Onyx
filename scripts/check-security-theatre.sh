#!/bin/bash

# Script: check-security-theatre.sh
# Description: Détecte automatiquement le "security theatre" dans le code Rust.
# Usage: ./scripts/check-security-theatre.sh [-v] [/path/to/scan]

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

# --- Définition des motifs de détection ---
declare -A PATTERNS

PATTERNS["Patterns interdits"]='.unwrap\s*\(\s*\)|\.expect\s*\(\s*""\s*\)|println!|print!|eprintln!|eprint!|dbg!'
PATTERNS["Placeholders"]='//.*Placeholder|//.*TODO|//.*FIXME|//.*XXX|//.*HACK|//.*TEMP|//.*Temporary|//.*FIX.*THIS|//.*REMOVE.*THIS'
PATTERNS["Code mort"]='unimplemented!|todo!|panic!|unreachable!|unreachable_unchecked!'
PATTERNS["Suppositions"]='should.*work|might.*work|probably.*works|assume|hope|guess|think.*it.*works|believe.*it.*works'
PATTERNS["Credentials hardcodés"]='password\s*=\s*"|secret\s*=\s*"|private_key\s*=\s*"|token\s*=\s*"|api_key\s*=\s*"'

# --- Initialisation ---
echo -e "${CYAN}Security Theatre Detection${NC}"
echo -e "${CYAN}=============================${NC}"
echo

declare -A issues_by_category
all_issues=()
total_issues=0

# --- Chargement des exceptions ---
exceptions=()
if [ -f "$IGNORE_FILE" ]; then
    while IFS= read -r line || [[ -n "$line" ]]; do
        # Ignore comments and empty lines
        if [[ ! "$line" =~ ^\s*# ]] && [[ -n "$line" ]]; then
            exceptions+=("$line")
        fi
    done < "$IGNORE_FILE"
    if [ "$VERBOSE" = true ]; then
        echo -e "${YELLOW}Loaded ${#exceptions[@]} exceptions from $IGNORE_FILE${NC}"
    fi
fi

# --- Fonction de vérification des exceptions ---
is_ignored() {
    local file_path=$1
    local line_content=$2

    # Normalize file path - remove leading ./
    file_path="${file_path#./}"

    for exc in "${exceptions[@]}"; do
        # Format: path/pattern:regex_pattern
        if [[ "$exc" =~ (.+):(.+) ]]; then
            local file_pattern="${BASH_REMATCH[1]}"
            local line_pattern="${BASH_REMATCH[2]}"

            # Convert glob pattern to regex for matching
            # ** matches zero or more path segments (including empty)
            # * matches any characters except /
            local regex_pattern="${file_pattern}"
            # Replace **/ with placeholder (preserves slash handling)
            regex_pattern="${regex_pattern//\*\*\//__DOUBLESTAR__}"
            # Replace remaining * with [^/]*
            regex_pattern="${regex_pattern//\*/[^/]*}"
            # Replace placeholder with optional path prefix
            regex_pattern="${regex_pattern//__DOUBLESTAR__/(.*/)?}"

            # Check if file path matches pattern and line content matches regex
            if [[ "$file_path" =~ $regex_pattern ]]; then
                if [[ "$line_content" =~ $line_pattern ]]; then
                    return 0 # 0 for true in bash functions
                fi
            fi
        fi
    done
    return 1 # 1 for false
}

# --- Scan des fichiers ---
rust_files=$(find "$SCAN_PATH" -name "*.rs" -not -path "*/target/*" -not -path "*/.git/*" -not -path "*/tests/*")
file_count=$(echo "$rust_files" | wc -w)
echo -e "${YELLOW}Scanning $file_count Rust files (excluding tests)...${NC}"
echo

for category in "${!PATTERNS[@]}"; do
    pattern_group=${PATTERNS[$category]}
    # grep returns non-zero if no lines selected, which would exit the script with `set -e`
    # So we use `|| true` to prevent that.
    # Exclude tests directory as per .security-theatre-ignore policy
    grep_results=$(grep -r -n -E --include="*.rs" --exclude-dir={target,.git,tests} "$pattern_group" "$SCAN_PATH" || true)

    if [ -n "$grep_results" ]; then
        while IFS= read -r line; do
            if [[ "$line" =~ ([^:]+):([0-9]+):(.*) ]]; then
                file="${BASH_REMATCH[1]}"
                line_num="${BASH_REMATCH[2]}"
                content="${BASH_REMATCH[3]}"
                
                # Trim leading/trailing whitespace from content
                trimmed_content=$(echo "$content" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')

                if ! is_ignored "$file" "$trimmed_content"; then
                    ((total_issues++))
                    issues_by_category[$category]=$((issues_by_category[$category]+1))
                    all_issues+=("$file:$line_num:$category:$trimmed_content")

                    if [ "$VERBOSE" = true ]; then
                        echo -e "${RED}❌ $category${NC}"
                        echo -e "   ${GRAY}${file}:${line_num}${NC}"
                        echo -e "   ${GRAY}$trimmed_content${NC}"
                        echo
                    fi
                fi
            fi
        done <<< "$grep_results"
    fi
done

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

# Rapport par catégorie
echo -e "${YELLOW}Issues by Category:${NC}"
for category in "${!issues_by_category[@]}"; do
    count=${issues_by_category[$category]}
    if [ $count -gt 0 ]; then
        echo -e "  $category: $count"
    fi
done
echo

# Top 10 des issues
echo -e "${RED}Top Issues:${NC}"
for issue in "${all_issues[@]:0:10}"; do
    IFS=':' read -r file line_num category content <<< "$issue"
    echo -e "  ${RED}$file:$line_num - $category${NC}"
    echo -e "    ${GRAY}$content${NC}"
done
echo

# Recommandations
echo -e "${YELLOW}Recommendations:${NC}"
echo -e "  1. Replace .unwrap() with proper error handling."
echo -e "  2. Remove placeholder comments and implement real code."
echo -e "  3. Use constants instead of magic numbers."
echo

echo -e "${CYAN}To temporarily bypass (with justification):${NC}"
echo -e "  1. Add exception to $IGNORE_FILE"

echo -e "${RED}❌ COMMIT BLOCKED - Fix security theatre issues first${NC}"
exit 1