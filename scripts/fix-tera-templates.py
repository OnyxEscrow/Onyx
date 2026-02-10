#!/usr/bin/env python3
"""
Fix Tera template syntax errors in Monero Marketplace templates.

This script fixes:
1. Removes 'with' parameters from include statements
2. Replaces dictionary syntax with if/elif chains
3. Fixes ternary conditions (a if condition else b) with if/else blocks
"""

import re
import os
from pathlib import Path

# Base template directory
TEMPLATES_DIR = Path("/home/malix/Desktop/monero.marketplace/templates")

def fix_include_with(content):
    """Remove 'with' parameters from include statements."""
    # Pattern: {% include "file" with param=value %}
    # Replace with: {% include "file" %}
    # This handles both single-line and multiline includes
    pattern = r'{%\s*include\s+"([^"]+)"\s+with[\s\S]*?%}'
    replacement = r'{% include "\1" %}'
    return re.sub(pattern, replacement, content)

def fix_toast_dictionary(content):
    """Fix dictionary syntax in toast.html by replacing with if/elif chain."""
    # Look for the default_icons dictionary pattern
    dict_pattern = r'{%\s*set\s+default_icons\s*=\s*\{[^}]*\}\s*%}'

    if re.search(dict_pattern, content):
        # Replace the entire dictionary block with if/elif chain
        # The dictionary maps type -> icon, we'll use conditional logic instead
        replacement = """{% if type == "success" %}
  {% set icon = "check-circle" %}
{% elif type == "error" %}
  {% set icon = "x-circle" %}
{% elif type == "warning" %}
  {% set icon = "alert-triangle" %}
{% elif type == "info" %}
  {% set icon = "info" %}
{% else %}
  {% set icon = "bell" %}
{% endif %}"""

        content = re.sub(dict_pattern, replacement, content)

        # Also replace usage of default_icons[type] with just icon
        content = re.sub(r'default_icons\[type\]', 'icon', content)

    return content

def fix_ternary_condition(content):
    """Fix ternary conditions: 'a if condition else b' -> if/else block."""
    # This is tricky because it's inside a {{ }} expression
    # Pattern: {{ char if char != ' ' else '&nbsp;' | safe }}

    # Find the problematic pattern in hero.html
    ternary_pattern = r'\{\{\s*(\w+)\s+if\s+([^}]+?)\s+else\s+([^}|]+?)(\s*\|\s*\w+)?\s*\}\}'

    def replace_ternary(match):
        var = match.group(1)
        condition = match.group(2)
        else_value = match.group(3)
        filter_part = match.group(4) or ''

        # Create an if/else block
        return f"""{{% if {condition} %}}{{{{{ var }{filter_part} }}}}{{% else %}}{{{{{ else_value }{filter_part} }}}}{{% endif %}}"""

    return re.sub(ternary_pattern, replace_ternary, content)

def fix_hero_spacing(content):
    """Special fix for hero.html letter spacing issue."""
    # The specific problematic line in hero.html
    # {{ char if char != ' ' else '&nbsp;' | safe }}
    # Need to replace with proper if/else

    pattern = r'<span class="nexus-hero-letter"[^>]*>\{\{\s*char\s+if\s+char\s*!=\s*[\'"]?\s+[\'"]?\s+else\s+[\'"]&nbsp;[\'"].*?\}\}</span>'

    if re.search(pattern, content):
        # Replace with proper if/else block
        replacement = '''<span class="nexus-hero-letter" style="--i: {{ loop.index0 }}">{% if char != ' ' %}{{ char | safe }}{% else %}&nbsp;{% endif %}</span>'''
        content = re.sub(pattern, replacement, content)

    return content

def process_file(filepath):
    """Process a single template file."""
    print(f"Processing: {filepath}")

    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()

        original_content = content

        # Apply fixes
        content = fix_include_with(content)
        content = fix_toast_dictionary(content)
        content = fix_ternary_condition(content)
        content = fix_hero_spacing(content)

        # Only write if content changed
        if content != original_content:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(content)
            print(f"  ✓ Fixed: {filepath}")
            return True
        else:
            print(f"  - No changes: {filepath}")
            return False

    except Exception as e:
        print(f"  ✗ Error processing {filepath}: {e}")
        return False

def main():
    """Main function to process all template files."""
    print("=" * 60)
    print("Tera Template Syntax Fixer")
    print("=" * 60)

    # Files with known errors (from server log)
    error_files = [
        # Molecules
        "partials/nexus/molecules/toast.html",
        "partials/nexus/molecules/product-card.html",
        "partials/nexus/molecules/category-card.html",
        "partials/nexus/molecules/card.html",

        # Organisms
        "partials/nexus/organisms/hero.html",
        "partials/nexus/organisms/escrow-visualizer.html",
        "partials/nexus/organisms/search-bar.html",
        "partials/nexus/organisms/order-timeline.html",

        # Other partials
        "partials/listing-form.html",

        # Pages
        "settings/index.html",
        "settings/wallet.html",
        "orders/index.html",
        "orders/show.html",
        "auth/register.html",
        "auth/login.html",
        "listings/edit.html",
        "listings/create.html",
        "listings/index.html",
        "listings/show.html",
    ]

    fixed_count = 0

    for rel_path in error_files:
        filepath = TEMPLATES_DIR / rel_path
        if filepath.exists():
            if process_file(filepath):
                fixed_count += 1
        else:
            print(f"  ✗ File not found: {filepath}")

    print("=" * 60)
    print(f"Fixed {fixed_count} files")
    print("=" * 60)

if __name__ == "__main__":
    main()
