#!/bin/bash

# Script: update-metrics.sh
# Description: Collecte et met à jour les métriques du projet.

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

echo -e "${CYAN}Collecte des métriques - $current_timestamp${NC}"

# --- Collecte ---

# Fichiers à analyser
rust_files=$(find . -path ./target -prune -o -name "*.rs" -print)

# 1. Lignes de code
total_lines=$(cat $rust_files | wc -l)

# 2. Nombre de fonctions publiques
function_count=$(grep -h -E "pub\s+(async\s+)?fn\s+\w+" $rust_files | wc -l)

# 3. Nombre de specs
spec_count=$(find docs/specs -name "*.md" | wc -l)

# 4. Nombre d'unwraps
unwrap_count=$(grep -h "\.unwrap(" $rust_files | wc -l)

# 5. Nombre de TODOs
todo_count=$(grep -h -i -E "TODO|FIXME" $rust_files | wc -l)

# 6. Nombre de fichiers de test
test_files_count=$(find . -path ./target -prune -o -name "*test*.rs" -print | wc -l)

# 7. Estimation de la couverture
coverage_estimate=0
if [ $function_count -gt 0 ]; then
    coverage_estimate=$(awk -v tests="$test_files_count" -v funcs="$function_count" 'BEGIN { printf "%.1f", (tests/funcs)*100 }')
fi

# --- Sauvegarde en JSON ---
json_file="$metrics_dir/daily-$current_date.json"

cat << EOF > "$json_file"
{
  "date": "$current_date",
  "timestamp": "$current_timestamp",
  "lines_of_code": $total_lines,
  "functions": $function_count,
  "specs": $spec_count,
  "unwraps": $unwrap_count,
  "todos": $todo_count,
  "test_files": $test_files_count,
  "coverage_estimate": $coverage_estimate
}
EOF

# --- Affichage ---
echo -e "\n${GREEN}MÉTRIQUES COLLECTÉES:${NC}"
echo -e "  ${WHITE}Lignes de code: $total_lines${NC}"
echo -e "  ${WHITE}Fonctions: $function_count${NC}"
echo -e "  ${WHITE}Specs: $spec_count${NC}"

# Affichage conditionnel des couleurs
color=$GREEN
if [ $unwrap_count -gt 0 ]; then color=$YELLOW; fi
if [ $unwrap_count -gt 5 ]; then color=$RED; fi
echo -e "  ${color}Unwraps: $unwrap_count${NC}"

color=$GREEN
if [ $todo_count -gt 0 ]; then color=$YELLOW; fi
if [ $todo_count -gt 10 ]; then color=$RED; fi
echo -e "  ${color}TODOs: $todo_count${NC}"

echo -e "  ${WHITE}Fichiers de test: $test_files_count${NC}"
echo -e "  ${WHITE}Couverture Est.: $coverage_estimate%${NC}"

# --- Vérification des seuils ---
warnings=()
errors=()

if [ $total_lines -gt 10000 ]; then errors+=("LOC très élevé (>10000)"); 
elif [ $total_lines -gt 5000 ]; then warnings+=("LOC élevé (>5000)"); fi

if [ $unwrap_count -gt 10 ]; then errors+=("Beaucoup trop d'unwraps (>10)");
elif [ $unwrap_count -gt 5 ]; then warnings+=("Trop d'unwraps (>5)"); fi

if [ $todo_count -gt 20 ]; then errors+=("Beaucoup trop de TODOs (>20)");
elif [ $todo_count -gt 10 ]; then warnings+=("Trop de TODOs (>10)"); fi

if [ $function_count -gt 0 ] && [ $spec_count -lt $function_count ]; then warnings+=("Fonctions sans spec"); fi

if [ ${#warnings[@]} -gt 0 ]; then
    echo -e "\n${YELLOW}WARNINGS:${NC}"
    for warning in "${warnings[@]}"; do
        echo -e "  - $warning"
    done
fi

if [ ${#errors[@]} -gt 0 ]; then
    echo -e "\n${RED}ERRORS:${NC}"
    for error in "${errors[@]}"; do
        echo -e "  - $error"
    done
fi

if [ ${#warnings[@]} -eq 0 ] && [ ${#errors[@]} -eq 0 ]; then
    echo -e "\n${GREEN}Toutes les métriques sont dans les seuils acceptables!${NC}"
fi

echo -e "\n${CYAN}Métriques sauvegardées: $json_file${NC}"
