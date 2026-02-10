#!/bin/bash
# SWISSY: A comprehensive audit script for the Monero Marketplace.

# --- Configuration ---
set -o pipefail
export TERM=xterm-256color

# --- Colors ---
RED=$(tput setaf 1)
GREEN=$(tput setaf 2)
YELLOW=$(tput setaf 3)
BLUE=$(tput setaf 4)
NC=$(tput sgr0) # No Color

# --- Globals ---
SCORE=100
ISSUES=0
VERBOSE=false
STRICT_MODE=false
JSON_OUTPUT=false
HTML_OUTPUT=false
RESULTS=()

# --- Functions ---

# Helper for printing sections
print_section() {
    if [ "$JSON_OUTPUT" = false ] && [ "$HTML_OUTPUT" = false ]; then
        echo -e "\n${BLUE}=======================================================================${NC}"
        echo -e "${BLUE}  $1${NC}"
        echo -e "${BLUE}=======================================================================${NC}"
    fi
}

# Helper for printing results
print_result() {
    local status=$1
    local message=$2
    local severity=$3
    local points=$4
    local location=${5:-"N/A"}

    RESULTS+=("$status|$severity|$message|$location")

    if [ "$JSON_OUTPUT" = false ] && [ "$HTML_OUTPUT" = false ]; then
        local location_text=""
        if [ "$location" != "N/A" ]; then
            location_text=" (${YELLOW}$location${NC})"
        fi

        case $status in
            "PASS")
                echo -e "  [${GREEN}✔${NC}] ${message}"
                ;;
            "FAIL")
                echo -e "  [${RED}✖${NC}] ${message}${location_text}"
                ISSUES=$((ISSUES + 1))
                SCORE=$((SCORE - points))
                ;;
            "WARN")
                echo -e "  [${YELLOW}⚠${NC}] ${message}${location_text}"
                if [ "$STRICT_MODE" = true ]; then
                    ISSUES=$((ISSUES + 1))
                    SCORE=$((SCORE - points))
                fi
                ;;
            "INFO")
                echo -e "  [${BLUE}ℹ${NC}] ${message}"
                ;;
        esac
    fi
}

# --- Report Generation ---
generate_json_report() {
    echo "{"
    echo "  \"summary\": {"
    echo "    \"score\": $SCORE,"
    echo "    \"issues\": $ISSUES"
    echo "  },"
    echo "  \"results\": ["
    for i in "${!RESULTS[@]}"; do
        IFS='|' read -r status severity message location <<< "${RESULTS[$i]}"
        # Escape quotes in message for valid JSON
        message=$(echo "$message" | sed 's/"/\\"/g')
        echo "    {"
        echo "      \"status\": \"$status\","
        echo "      \"severity\": \"$severity\","
        echo "      \"message\": \"$message\","
        echo "      \"location\": \"$location\""
        echo "    }"
        if [ $i -lt $((${#RESULTS[@]} - 1)) ]; then
            echo ","
        fi
    done
    echo "  ]"
    echo "}"
}

generate_html_report() {
    cat <<EOF
<!DOCTYPE html>
<html>
<head>
<title>Swissy Audit Report</title>
<style>
  body { font-family: sans-serif; margin: 2em; background-color: #f8f9fa; color: #212529; }
  h1, h2 { color: #343a40; }
  .summary { background-color: #e9ecef; padding: 1em; border-radius: 0.5em; }
  .results { list-style-type: none; padding: 0; }
  .result { margin: 0.5em 0; padding: 1em; border-left: 5px solid; border-radius: 0.25em; background-color: #fff; }
  .result strong { font-size: 1.1em; }
  .location { font-family: monospace; color: #888; font-size: 0.9em; }
  .PASS { border-color: #28a745; }
  .FAIL { border-color: #dc3545; }
  .WARN { border-color: #ffc107; }
  .INFO { border-color: #17a2b8; }
</style>
</head>
<body>
<h1>Swissy Audit Report</h1>
<div class="summary">
  <h2>Summary</h2>
  <p><strong>Score:</strong> $SCORE/100</p>
  <p><strong>Total Issues:</strong> $ISSUES</p>
</div>
<h2>Details</h2>
<ul class="results">
EOF

    for result in "${RESULTS[@]}"; do
        IFS='|' read -r status severity message location <<< "$result"
        echo "<li class=\"result $status\"><strong>[$status]</strong> ($severity) $message"
        if [ "$location" != "N/A" ]; then
            echo "<br><span class=\"location\">$location</span>"
        fi
        echo "</li>"
    done

    cat <<EOF
</ul>
</body>
</html>
EOF
}


# --- Audit Categories ---

audit_infrastructure() {
    print_section "Category 1: Critical Infrastructure"
    
    if [ -f "database/src/schema.rs" ]; then
        print_result "PASS" "schema.rs file found." "CRITICAL" 0
    else
        print_result "FAIL" "schema.rs file NOT found. This is a blocking issue." "CRITICAL" 25 "database/src/schema.rs"
    fi

    if [ -f ".env" ]; then
        print_result "PASS" ".env file found." "CRITICAL" 0
    else
        print_result "FAIL" ".env file NOT found. Configuration is missing." "CRITICAL" 15 ".env"
    fi
    
    if [ -f "diesel.toml" ]; then
        print_result "PASS" "diesel.toml file found." "CRITICAL" 0
    else
        print_result "FAIL" "diesel.toml file NOT found. Database configuration is missing." "CRITICAL" 15 "diesel.toml"
    fi
}


audit_security() {
    print_section "Category 2: Critical Security"

    # Scan for hardcoded secrets
    local secrets
    secrets=$(grep -n -r -E 'password|secret|key|token' --exclude-dir=node_modules --exclude-dir=.git --exclude-dir=target .)
    if [ -z "$secrets" ]; then
        print_result "PASS" "No obvious hardcoded secrets found." "CRITICAL" 0
    else
        while IFS= read -r line; do
            print_result "WARN" "Potential hardcoded secret found." "CRITICAL" 10 "$line"
        done <<< "$secrets"
    fi

    if grep -q ".env" .gitignore; then
        print_result "PASS" ".env is in .gitignore." "CRITICAL" 0
    else
        print_result "FAIL" ".env is NOT in .gitignore. This is a major security risk." "CRITICAL" 20 ".gitignore"
    fi
}

audit_config() {
    print_section "Category 3: Configuration services (HAUTE PRIORITÉ)"

    if pgrep -x "tor" > /dev/null; then
        print_result "PASS" "Tor daemon is running." "HIGH" 0
    else
        print_result "WARN" "Tor daemon is not running." "HIGH" 5
    fi
}

audit_quality() {
    print_section "Category 4: Code quality"

    # Find .unwrap() calls
    local unwraps
    unwraps=$(grep -n -r ".unwrap()" --include=\*.rs .)
    if [ -z "$unwraps" ]; then
        print_result "PASS" "No .unwrap() calls found." "HIGH" 0
    else
        while IFS= read -r line; do
            print_result "WARN" "Found .unwrap() call." "HIGH" 1 "$line"
        done <<< "$unwraps"
    fi

    # Find TODO/FIXME comments
    local todos
    todos=$(grep -n -r -E 'TODO|FIXME' --exclude-dir=node_modules --exclude-dir=.git --exclude-dir=target .)
    if [ -z "$todos" ]; then
        print_result "PASS" "No TODO or FIXME comments found." "HIGH" 0
    else
        while IFS= read -r line; do
            print_result "WARN" "Found TODO/FIXME comment." "HIGH" 1 "$line"
        done <<< "$todos"
    fi
}


audit_tests() {
    print_section "Category 5: Tests (HAUTE PRIORITÉ)"

    if cargo test --workspace --quiet -- --nocapture; then
        print_result "PASS" "All tests passed." "HIGH" 0
    else
        print_result "FAIL" "Some tests failed. Please review." "HIGH" 15
    fi
}

audit_database() {
    print_section "Category 6: Database integrity (MOYENNE PRIORITÉ)"

    print_result "INFO" "Database integrity check is a placeholder." "MEDIUM" 0
}

audit_documentation() {
    print_section "Category 7: Documentation"

    if [ -f "README.md" ]; then
        print_result "PASS" "README.md found." "MEDIUM" 0
    else
        print_result "WARN" "README.md not found." "MEDIUM" 2 "README.md"
    fi

    if [ -f "docs/AUDIT.md" ]; then
        print_result "PASS" "docs/AUDIT.md found." "MEDIUM" 0
    else
        print_result "WARN" "docs/AUDIT.md not found." "MEDIUM" 2 "docs/AUDIT.md"
    fi
}


audit_build() {
    print_section "Category 8: Build & compilation (MOYENNE PRIORITÉ)"

    if cargo check --workspace --quiet; then
        print_result "PASS" "cargo check passed." "MEDIUM" 0
    else
        print_result "FAIL" "cargo check failed." "MEDIUM" 10
    fi
}

audit_git() {
    print_section "Category 9: Git hygiene"

    if [ -f ".gitignore" ]; then
        print_result "PASS" ".gitignore found." "LOW" 0
    else
        print_result "WARN" ".gitignore not found." "LOW" 1 ".gitignore"
    fi
}

audit_performance() {
    print_section "Category 10: Performance & monitoring (BASSE PRIORITÉ)"

    print_result "INFO" "Performance check is a placeholder." "LOW" 0
}


# --- Main Execution ---
main() {
    # Parse arguments
    for arg in "$@"; do
        case $arg in
            --json)
            JSON_OUTPUT=true
            shift
            ;;
            --html)
            HTML_OUTPUT=true
            shift
            ;;
            --strict)
            STRICT_MODE=true
            shift
            ;;
            -v|--verbose)
            VERBOSE=true
            shift
            ;;
        esac
    done

    # Run audits
    audit_infrastructure
    audit_security
    audit_config
    audit_quality
    audit_tests
    audit_database
    audit_documentation
    audit_build
    audit_git
    audit_performance
    
    # Generate reports or print summary
    if [ "$JSON_OUTPUT" = true ]; then
        generate_json_report
    elif [ "$HTML_OUTPUT" = true ]; then
        generate_html_report
    else
        echo -e "\n${BLUE}=======================================================================${NC}"
        echo -e "${BLUE}  Audit Complete${NC}"
        echo -e "${BLUE}=======================================================================${NC}"
        echo -e "  Final Score: ${GREEN}${SCORE}/100${NC}"
        echo -e "  Total Issues: ${RED}${ISSUES}${NC}"
    fi

    if [ "$ISSUES" -gt 0 ]; then
        exit 1
    else
        exit 0
    fi
}

main "$@"
