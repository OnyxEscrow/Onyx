#!/bin/bash
# Minify Nexus CSS for production deployment
# Requires: csso-cli (npm install -g csso-cli)
# Or can use sed for basic minification if csso not available

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
CSS_DIR="$PROJECT_ROOT/static/css"

echo "🎨 NEXUS CSS Minification"
echo "========================="
echo ""

cd "$CSS_DIR"

# Check if csso is available
if command -v csso &> /dev/null; then
    echo "✅ Using csso-cli for minification"
    echo ""

    # Minify each Nexus CSS file
    FILES=("nexus-variables.css" "nexus-reset.css" "nexus-animations.css" "nexus.css")

    for file in "${FILES[@]}"; do
        if [ -f "$file" ]; then
            echo "→ Minifying $file..."
            csso "$file" -o "${file%.css}.min.css"

            # Get file sizes
            ORIGINAL_SIZE=$(stat -f%z "$file" 2>/dev/null || stat -c%s "$file")
            MINIFIED_SIZE=$(stat -f%z "${file%.css}.min.css" 2>/dev/null || stat -c%s "${file%.css}.min.css")
            REDUCTION=$((100 - (MINIFIED_SIZE * 100 / ORIGINAL_SIZE)))

            echo "   Original:  $(numfmt --to=iec-i --suffix=B $ORIGINAL_SIZE 2>/dev/null || echo "${ORIGINAL_SIZE}B")"
            echo "   Minified:  $(numfmt --to=iec-i --suffix=B $MINIFIED_SIZE 2>/dev/null || echo "${MINIFIED_SIZE}B")"
            echo "   Reduction: ${REDUCTION}%"
            echo ""
        fi
    done

else
    echo "⚠️  csso-cli not found, using basic minification with sed"
    echo "   Install csso for better compression: npm install -g csso-cli"
    echo ""

    # Basic minification using sed (removes comments, whitespace)
    FILES=("nexus-variables.css" "nexus-reset.css" "nexus-animations.css" "nexus.css")

    for file in "${FILES[@]}"; do
        if [ -f "$file" ]; then
            echo "→ Minifying $file (basic)..."

            # Remove comments and excessive whitespace
            sed -e 's/\/\*.*\*\///g' \
                -e 's/^[[:space:]]*//g' \
                -e 's/[[:space:]]*$//g' \
                -e '/^$/d' \
                "$file" > "${file%.css}.min.css"

            # Get file sizes
            ORIGINAL_SIZE=$(stat -f%z "$file" 2>/dev/null || stat -c%s "$file")
            MINIFIED_SIZE=$(stat -f%z "${file%.css}.min.css" 2>/dev/null || stat -c%s "${file%.css}.min.css")
            REDUCTION=$((100 - (MINIFIED_SIZE * 100 / ORIGINAL_SIZE)))

            echo "   Original:  ${ORIGINAL_SIZE}B"
            echo "   Minified:  ${MINIFIED_SIZE}B"
            echo "   Reduction: ${REDUCTION}%"
            echo ""
        fi
    done
fi

# Create combined minified bundle
echo "→ Creating combined bundle: nexus-bundle.min.css"
cat nexus-variables.min.css \
    nexus-reset.min.css \
    nexus-animations.min.css \
    nexus.min.css > nexus-bundle.min.css

BUNDLE_SIZE=$(stat -f%z "nexus-bundle.min.css" 2>/dev/null || stat -c%s "nexus-bundle.min.css")
BUNDLE_SIZE_KB=$((BUNDLE_SIZE / 1024))

echo "   Bundle size: ${BUNDLE_SIZE_KB}KB"
echo ""

# Check if under 25KB target
if [ $BUNDLE_SIZE_KB -lt 25 ]; then
    echo "✅ SUCCESS: Bundle under 25KB target (Tor-optimized)"
else
    echo "⚠️  WARNING: Bundle over 25KB target ($BUNDLE_SIZE_KB KB)"
    echo "   Consider removing unused CSS or further optimization"
fi

echo ""
echo "📊 Minification Summary"
echo "======================"
echo "Files created:"
echo "  - nexus-variables.min.css"
echo "  - nexus-reset.min.css"
echo "  - nexus-animations.min.css"
echo "  - nexus.min.css"
echo "  - nexus-bundle.min.css (combined)"
echo ""
echo "✅ Minification complete!"
