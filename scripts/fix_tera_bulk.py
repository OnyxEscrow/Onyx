#!/usr/bin/env python3
"""
Bulk fix Tera template syntax errors.
Removes all "with" parameters from include statements.
"""

import re
import os
from pathlib import Path

def fix_include_with(content):
    """Remove 'with' parameters from include statements."""
    # Pattern: {% include "file.html" with ... %}
    # Replace with: {% include "file.html" %}
    pattern = r'{%\s*include\s+"([^"]+)"\s+with[^}]*%}'
    replacement = r'{% include "\1" %}'
    return re.sub(pattern, replacement, content, flags=re.MULTILINE | re.DOTALL)

def main():
    templates_dir = Path("templates")
    fixed_count = 0

    print("🔧 Fixing Tera templates...")

    # Find all .html files
    for html_file in templates_dir.rglob("*.html"):
        with open(html_file, 'r', encoding='utf-8') as f:
            original = f.read()

        # Apply fix
        fixed = fix_include_with(original)

        # Only write if changed
        if fixed != original:
            with open(html_file, 'w', encoding='utf-8') as f:
                f.write(fixed)
            print(f"  ✅ Fixed: {html_file}")
            fixed_count += 1

    print(f"\n✅ Fixed {fixed_count} files")
    print("📝 Note: alert.html, toast.html, nav.html, footer.html, hero.html need manual dictionary/ternary fixes")

if __name__ == "__main__":
    main()
