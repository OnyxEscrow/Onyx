#!/bin/bash

# Real Frontend Audit - No Theatre Edition
# Only checks things that actually matter and can be verified properly
# Exit codes: 0=Good enough, 1=Needs fixes, 2=Broken

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

# Colors
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

CRITICAL=0
WARNINGS=0

critical() {
    echo -e "${RED}✗ CRITICAL:${NC} $1"
    ((CRITICAL++))
}

warning() {
    echo -e "${YELLOW}⚠ WARNING:${NC} $1"
    ((WARNINGS++))
}

ok() {
    echo -e "${GREEN}✓${NC} $1"
}

section() {
    echo -e "\n${CYAN}━━━ $1 ━━━${NC}"
}

# ============================================================================
# 1. ACCESSIBILITY - ACTUAL CHECKS
# ============================================================================

check_real_accessibility() {
    section "Real Accessibility Checks"

    # Check for empty alt attributes (actually broken)
    EMPTY_ALT=$(grep -rn 'alt=""' templates/ 2>/dev/null | wc -l)
    GENERIC_ALT=$(grep -rin 'alt="image"\|alt="photo"\|alt="icon"\|alt="picture"' templates/ 2>/dev/null | wc -l)

    if [ "$EMPTY_ALT" -eq 0 ] && [ "$GENERIC_ALT" -eq 0 ]; then
        ok "No empty or generic alt text found"
    else
        if [ "$EMPTY_ALT" -gt 0 ]; then
            critical "Found $EMPTY_ALT images with empty alt=\"\" (not decorative images)"
            grep -rn 'alt=""' templates/ 2>/dev/null | head -5 | sed 's/^/    /'
        fi
        if [ "$GENERIC_ALT" -gt 0 ]; then
            warning "Found $GENERIC_ALT images with generic alt text (image/photo/icon)"
            grep -rin 'alt="image"\|alt="photo"\|alt="icon"' templates/ 2>/dev/null | head -3 | sed 's/^/    /'
        fi
    fi

    # Check for images without alt at all
    IMGS_TOTAL=$(grep -rn '<img' templates/ 2>/dev/null | wc -l)
    IMGS_WITH_ALT=$(grep -rn '<img[^>]*alt=' templates/ 2>/dev/null | wc -l)
    MISSING=$((IMGS_TOTAL - IMGS_WITH_ALT))

    if [ "$MISSING" -gt 0 ]; then
        critical "$MISSING images missing alt attribute entirely"
        grep -rn '<img' templates/ 2>/dev/null | grep -v 'alt=' | head -5 | sed 's/^/    /'
    else
        ok "All $IMGS_TOTAL images have alt attribute"
    fi

    # Check for inputs without labels (proper check with exit code)
    section "Form Label Check"

    if [ -d "templates/" ]; then
        python3 - <<'EOF'
import re
import os
from pathlib import Path

issues = []
for path in Path("templates").rglob("*.html"):
    try:
        with open(path) as f:
            content = f.read()
    except:
        continue

    # Find inputs with IDs
    inputs = re.findall(r'<input[^>]*id=["\']([^"\']+)["\']', content)

    for input_id in inputs:
        # Check if there's a label for this ID
        if not re.search(rf'<label[^>]*for=["\']?{re.escape(input_id)}["\']?', content):
            issues.append(f"{path}: Input #{input_id} has no <label for=...>")

if issues:
    print(f"FOUND {len(issues)} inputs without proper labels:")
    for issue in issues[:10]:  # Show first 10
        print(f"  {issue}")
    import sys
    sys.exit(1)
else:
    print("OK: All inputs with IDs have corresponding labels")
EOF

        if [ $? -eq 1 ]; then
            warning "Inputs without proper labels found (see above)"
        fi
    fi

    # Check for actual focus styles (parse CSS properly)
    section "Keyboard Navigation"

    if [ -f "static/css/main.css" ] || [ -f "static/css/style.css" ] || [ -f "static/css/nexus-true.css" ]; then
        FOCUS_RULES=$(grep -A 3 ':focus' static/css/*.css 2>/dev/null | grep -c '{')

        if [ "$FOCUS_RULES" -gt 0 ]; then
            ok "Found $FOCUS_RULES actual :focus CSS rules"

            # Check if focus styles are being removed without alternative (IMPROVED)
            if grep -rq 'outline.*none\|outline.*0' static/css/*.css 2>/dev/null | grep -q ':focus'; then
                # Check for alternative visible indicators
                FOCUS_ALTERNATIVES=$(grep -A 5 ':focus' static/css/*.css 2>/dev/null | \
                    grep -E 'border[^:]*:|box-shadow:|background[^:]*:' | wc -l)

                if [ "$FOCUS_ALTERNATIVES" -eq 0 ]; then
                    critical "Focus outline removed WITHOUT alternative visible indicator"
                    grep -n 'outline.*none\|outline.*0' static/css/*.css 2>/dev/null | grep -B 2 ':focus' | head -5 | sed 's/^/    /'
                else
                    ok "Custom focus indicators defined (outline replaced with $FOCUS_ALTERNATIVES alternatives)"
                fi
            fi
        else
            critical "No :focus styles defined - keyboard users can't see where they are"
        fi
    fi

    # Check for proper heading hierarchy (with exit code)
    section "Heading Structure"

    python3 - <<'EOF'
import re
from pathlib import Path

issue_count = 0
for path in Path("templates").rglob("*.html"):
    try:
        with open(path) as f:
            content = f.read()
    except:
        continue

    # Extract all headings with their levels
    headings = re.findall(r'<h([1-6])[^>]*>.*?</h\1>', content, re.DOTALL)

    if not headings:
        continue

    levels = [int(h) for h in headings]

    # Check for skipped levels (h1 -> h3)
    issues = []
    for i in range(len(levels) - 1):
        if levels[i+1] - levels[i] > 1:
            issues.append(f"Skips from h{levels[i]} to h{levels[i+1]}")

    # Check for multiple h1s
    h1_count = levels.count(1)

    if issues or h1_count > 1:
        print(f"\n{path}:")
        if h1_count > 1:
            print(f"  ⚠ Multiple h1 tags ({h1_count})")
            issue_count += 1
        for issue in issues:
            print(f"  ⚠ {issue}")
            issue_count += 1

if issue_count > 0:
    import sys
    sys.exit(1)
EOF

    if [ $? -eq 1 ]; then
        warning "Heading hierarchy issues found (see above)"
    else
        ok "Heading structure is correct"
    fi
}

# ============================================================================
# 2. SECURITY - REAL CHECKS
# ============================================================================

check_real_security() {
    section "Security Checks"

    # Check for CSRF tokens in forms (improved with Python)
    check_csrf_tokens

    # Check for hardcoded secrets
    section "Hardcoded Secrets"

    SECRETS=$(grep -rniE 'password.*=.*["\'][^"\']{8,}["\']|api_key.*=.*["\'][^"\']+["\']|secret.*=.*["\'][^"\']+["\']' . \
        --include="*.py" --include="*.js" --include="*.html" --include="*.rs" \
        --exclude-dir=venv --exclude-dir=node_modules --exclude-dir=.git --exclude-dir=target 2>/dev/null | \
        grep -v 'password_hash\|password_field\|api_key_field\|test_password\|example' | wc -l)

    if [ "$SECRETS" -gt 0 ]; then
        critical "Possible hardcoded secrets found: $SECRETS occurrences"
        grep -rniE 'password.*=.*["\'][^"\']{8,}["\']|api_key.*=.*["\'][^"\']+["\']|secret.*=.*["\'][^"\']+["\']' . \
            --include="*.py" --include="*.js" --include="*.html" --include="*.rs" \
            --exclude-dir=venv --exclude-dir=node_modules --exclude-dir=.git --exclude-dir=target 2>/dev/null | \
            grep -v 'password_hash\|password_field\|api_key_field\|test_password\|example' | head -5 | sed 's/^/    /'
    else
        ok "No obvious hardcoded secrets"
    fi

    # Check for XSS risks (NEW)
    check_xss_risks

    # Check for SQL injection vulnerabilities (basic)
    if [ -d "server/src" ]; then
        SQL_CONCAT=$(grep -rn 'format!\|&format\|\+ &' server/src \
            --include="*.rs" 2>/dev/null | \
            grep -i 'query\|sql\|execute' | wc -l)

        if [ "$SQL_CONCAT" -gt 0 ]; then
            warning "Possible SQL string concatenation in Rust code: $SQL_CONCAT occurrences"
            echo "    Review these for SQL injection - should use diesel macros:"
            grep -rn 'format!\|&format\|\+ &' server/src \
                --include="*.rs" 2>/dev/null | \
                grep -i 'query\|sql\|execute' | head -3 | sed 's/^/    /'
        fi
    fi
}

check_csrf_tokens() {
    # Check for CSRF tokens in forms (proper check)
    FORMS_WITH_ACTION=$(grep -rn '<form' templates/ 2>/dev/null | grep -v 'method="get"' | wc -l)

    if [ "$FORMS_WITH_ACTION" -gt 0 ]; then
        FORMS_WITH_CSRF=0
        while IFS=: read -r file line; do
            if grep -q 'csrf' "$file"; then
                ((FORMS_WITH_CSRF++))
            fi
        done < <(grep -rl '<form' templates/ 2>/dev/null | grep -v 'method="get"' || true)

        if [ "$FORMS_WITH_CSRF" -lt "$FORMS_WITH_ACTION" ]; then
            critical "Found POST/PUT/DELETE forms without CSRF tokens"
        else
            ok "All POST/PUT/DELETE forms have CSRF protection"
        fi
    else
        ok "No forms to check for CSRF"
    fi
}

check_xss_risks() {
    section "XSS Risk Check"

    if [ -d "static/js" ]; then
        XSS_PATTERNS=$(grep -rn 'innerHTML\|eval(' static/js/*.js 2>/dev/null | \
            grep -v '\.min\.js' | wc -l)

        if [ "$XSS_PATTERNS" -gt 0 ]; then
            warning "Potentially unsafe JS patterns found: $XSS_PATTERNS"
            grep -rn 'innerHTML\|eval(' static/js/*.js 2>/dev/null | \
                grep -v '\.min\.js' | head -5 | sed 's/^/    /'
        else
            ok "No obvious XSS risks in JS"
        fi
    fi

    # Check for unescaped template variables
    if [ -d "templates/" ]; then
        UNESCAPED=$(grep -rn '{{[^{]*|safe' templates/ 2>/dev/null | wc -l)

        if [ "$UNESCAPED" -gt 0 ]; then
            warning "Found $UNESCAPED uses of |safe filter (ensure these are sanitized)"
            grep -rn '{{[^{]*|safe' templates/ 2>/dev/null | head -5 | sed 's/^/    /'
        fi
    fi
}

# ============================================================================
# 3. PERFORMANCE - MEASURABLE CHECKS
# ============================================================================

check_real_performance() {
    section "Performance Checks"

    # Check actual CSS file sizes
    if [ -d "static/css" ]; then
        CSS_SIZE=$(du -sh static/css 2>/dev/null | cut -f1)
        CSS_BYTES=$(du -sb static/css 2>/dev/null | cut -f1)

        if [ -n "$CSS_BYTES" ]; then
            if [ "$CSS_BYTES" -gt 204800 ]; then  # 200KB
                warning "CSS directory is $CSS_SIZE (consider minification)"
            elif [ "$CSS_BYTES" -gt 512000 ]; then  # 500KB
                critical "CSS directory is $CSS_SIZE (excessive, must optimize)"
            else
                ok "CSS size: $CSS_SIZE"
            fi
        fi
    fi

    # Check for unminified JS in production
    if [ -d "static/js" ]; then
        UNMINIFIED_JS=$(find static/js -name "*.js" ! -name "*.min.js" -type f 2>/dev/null | wc -l)

        if [ "$UNMINIFIED_JS" -gt 0 ]; then
            warning "$UNMINIFIED_JS unminified JS files in static/"
        fi
    fi

    # Check for missing image optimization
    if command -v identify &> /dev/null; then
        section "Image Optimization"

        LARGE_IMAGES=0
        if [ -d "static/img" ] || [ -d "static/images" ]; then
            while IFS= read -r img; do
                SIZE=$(du -k "$img" 2>/dev/null | cut -f1)
                if [ -n "$SIZE" ] && [ "$SIZE" -gt 500 ]; then  # 500KB
                    warning "Large image: $img (${SIZE}KB)"
                    ((LARGE_IMAGES++))
                fi
            done < <(find static/img static/images -type f \( -name "*.jpg" -o -name "*.png" \) 2>/dev/null)

            if [ "$LARGE_IMAGES" -eq 0 ]; then
                ok "No excessively large images found"
            fi
        fi
    fi
}

# ============================================================================
# 4. FUNCTIONALITY - REAL CHECKS
# ============================================================================

check_functionality() {
    section "Functionality Checks"

    # Check for broken internal links
    if [ -d "templates/" ]; then
        python3 - <<'EOF'
import re
from pathlib import Path

issues = []
for path in Path("templates").rglob("*.html"):
    try:
        with open(path) as f:
            content = f.read()
    except:
        continue

    # Find internal links
    links = re.findall(r'href=["\']([^"\']+)["\']', content)

    for link in links:
        # Skip external, anchors, and dynamic
        if link.startswith(('http', '#', 'javascript:', '{', 'mailto:', '//')):
            continue

        # Check if it's a static file reference
        if link.startswith('/static/'):
            file_path = Path(link[1:])  # Remove leading /
            if not file_path.exists():
                issues.append(f"{path}: Broken link to {link}")

if issues:
    print(f"FOUND {len(issues)} broken static links:")
    for issue in issues[:10]:
        print(f"  {issue}")
    import sys
    sys.exit(1)
else:
    print("OK: No obvious broken static links")
EOF

        if [ $? -eq 1 ]; then
            warning "Broken static links found (see above)"
        fi
    fi

    # Check for console.log in production code
    if [ -d "static/js" ]; then
        CONSOLE_LOGS=$(grep -rn 'console\.log\|console\.debug' static/js/*.js 2>/dev/null | \
            grep -v '\.min\.js' | wc -l)

        if [ "$CONSOLE_LOGS" -gt 0 ]; then
            warning "Found $CONSOLE_LOGS console.log() statements (remove for production)"
            grep -rn 'console\.log\|console\.debug' static/js/*.js 2>/dev/null | \
                grep -v '\.min\.js' | head -3 | sed 's/^/    /'
        fi
    fi
}

# ============================================================================
# 5. TOR/MONERO SPECIFIC CHECKS
# ============================================================================

check_monero_specific() {
    section "Monero/Tor Specific Checks"

    # Check for clearnet leaks
    CLEARNET_URLS=$(grep -rn 'https\?://[^o][^n][^i][^o][^n]' templates/ static/ 2>/dev/null | \
        grep -v 'localhost\|127.0.0.1\|example.com\|schema.org\|w3.org' | wc -l)

    if [ "$CLEARNET_URLS" -gt 0 ]; then
        critical "Possible clearnet URL leaks found: $CLEARNET_URLS"
        grep -rn 'https\?://[^o][^n][^i][^o][^n]' templates/ static/ 2>/dev/null | \
            grep -v 'localhost\|127.0.0.1\|example.com\|schema.org\|w3.org' | head -5 | sed 's/^/    /'
    else
        ok "No obvious clearnet leaks"
    fi

    # Check for analytics/tracking scripts
    TRACKING=$(grep -rin 'google-analytics\|gtag\|facebook\|twitter\|cloudflare' templates/ 2>/dev/null | wc -l)

    if [ "$TRACKING" -gt 0 ]; then
        critical "Tracking scripts found! ($TRACKING occurrences)"
        grep -rin 'google-analytics\|gtag\|facebook\|twitter\|cloudflare' templates/ 2>/dev/null | sed 's/^/    /'
    else
        ok "No tracking scripts detected"
    fi

    # Check for external resource loading (CDN)
    EXTERNAL=$(grep -rn 'src=.*https://\|href=.*https://' templates/ 2>/dev/null | \
        grep -v 'localhost\|127.0.0.1\|schema.org\|w3.org' | wc -l)

    if [ "$EXTERNAL" -gt 0 ]; then
        warning "External resources loading ($EXTERNAL) - review for Tor compatibility"
        grep -rn 'src=.*https://\|href=.*https://' templates/ 2>/dev/null | \
            grep -v 'localhost\|127.0.0.1\|schema.org\|w3.org' | head -5 | sed 's/^/    /'
    fi

    # Check for IP address leaks in logs/errors
    if [ -d "server/src" ]; then
        IP_LOGS=$(grep -rn 'tracing::info.*ip\|println.*ip\|log.*ip' server/src \
            --include="*.rs" 2>/dev/null | wc -l)

        if [ "$IP_LOGS" -gt 0 ]; then
            critical "Possible IP address logging in Rust code: $IP_LOGS"
            grep -rn 'tracing::info.*ip\|println.*ip\|log.*ip' server/src \
                --include="*.rs" 2>/dev/null | head -3 | sed 's/^/    /'
        else
            ok "No obvious IP logging in code"
        fi
    fi
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

main() {
    echo -e "${CYAN}╔═══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║      REAL FRONTEND AUDIT - NO THEATRE                     ║${NC}"
    echo -e "${CYAN}║      Only checks things that actually matter              ║${NC}"
    echo -e "${CYAN}╚═══════════════════════════════════════════════════════════╝${NC}"

    check_real_accessibility
    check_real_security
    check_real_performance
    check_functionality
    check_monero_specific

    # Summary
    echo -e "\n${CYAN}━━━ SUMMARY ━━━${NC}\n"

    if [ $CRITICAL -eq 0 ] && [ $WARNINGS -eq 0 ]; then
        echo -e "${GREEN}✓ No issues found${NC}"
        exit 0
    fi

    if [ $CRITICAL -gt 0 ]; then
        echo -e "${RED}✗ $CRITICAL CRITICAL issues${NC}"
    fi

    if [ $WARNINGS -gt 0 ]; then
        echo -e "${YELLOW}⚠ $WARNINGS warnings${NC}"
    fi

    echo ""

    if [ $CRITICAL -gt 0 ]; then
        echo -e "${RED}Fix critical issues before deploying${NC}"
        exit 2
    elif [ $WARNINGS -gt 5 ]; then
        echo -e "${YELLOW}Consider addressing warnings${NC}"
        exit 1
    else
        echo -e "${GREEN}Good enough to ship${NC}"
        exit 0
    fi
}

main "$@"
