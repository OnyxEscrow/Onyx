#!/bin/bash
#
# Fix Tera template syntax - remove "with" parameters
# Tera doesn't support {% include "file" with param=value %} syntax
#

set -e

echo "🔧 Fixing Tera template syntax..."

# Find all template files with "include" and "with"
files=$(grep -rl "include.*with" templates/ 2>/dev/null || true)

if [ -z "$files" ]; then
    echo "✅ No files to fix!"
    exit 0
fi

count=0
for file in $files; do
    echo "  Fixing: $file"

    # Remove multiline "with" blocks - replace with simple include
    # Pattern: {% include "..." with ... %} becomes {% include "..." %}
    perl -i -0pe 's/{%\s*include\s+"([^"]+)"\s+with[^}]*%}/{%include "$1"%}/gs' "$file"

    ((count++))
done

echo "✅ Fixed $count files"
echo ""
echo "📝 Note: Components now expect values from Rust context (logged_in, username, etc.)"
