#!/usr/bin/env python3
"""
Fix Tera template syntax errors - Version 2.

For components with complex multiline 'with' parameters:
- Replace entire card includes with simple placeholder comments
- These need proper Rust context redesign later
"""

import re
from pathlib import Path

TEMPLATES_DIR = Path("/home/malix/Desktop/monero.marketplace/templates")

def fix_orders_index(filepath):
    """Fix orders/index.html specifically."""
    with open(filepath, 'r') as f:
        content = f.read()

    # Fix the button include - just remove parameters
    content = re.sub(
        r'{%\s*include\s+"partials/nexus/atoms/button\.html"\s+with[\s\S]*?%}',
        '{% include "partials/nexus/atoms/button.html" %}',
        content,
        count=1
    )

    # Fix the tabs include - just remove it and add placeholder
    content = re.sub(
        r'{#\s*Filter Tabs\s*#}\s*{%\s*include\s+"partials/nexus/molecules/tabs\.html"\s+with[\s\S]*?%}',
        '{# Filter Tabs #}\n  {# TODO: Add tabs component with Rust context data #}',
        content
    )

    # Fix the card include inside the loop - replace with simple card structure
    old_pattern = r'{%\s*include\s+"partials/nexus/molecules/card\.html"\s+with[\s\S]*?%}'
    new_content = '''{# Card component - TODO: Use proper Rust context #}
        <div class="nexus-card">
          <h3>Order #{{ order.id }}</h3>
          <p>Status: {{ order.status }}</p>
          <p>Escrow: {{ order.escrow_id }}</p>
        </div>'''
    content = re.sub(old_pattern, new_content, content)

    # Fix the alert include in empty state
    content = re.sub(
        r'{%\s*include\s+"partials/nexus/molecules/alert\.html"\s+with[\s\S]*?%}',
        '{% include "partials/nexus/molecules/alert.html" %}',
        content
    )

    with open(filepath, 'w') as f:
        f.write(content)
    print(f"✓ Fixed: {filepath}")

def fix_orders_show(filepath):
    """Fix orders/show.html specifically."""
    with open(filepath, 'r') as f:
        content = f.read()

    # Remove all multiline includes with 'with'
    content = re.sub(
        r'{%\s*include\s+"[^"]+"\s+with[\s\S]*?%}',
        lambda m: '{% include "' + re.search(r'include\s+"([^"]+)"', m.group(0)).group(1) + '" %}',
        content
    )

    with open(filepath, 'w') as f:
        f.write(content)
    print(f"✓ Fixed: {filepath}")

def fix_listings_show(filepath):
    """Fix listings/show.html specifically."""
    with open(filepath, 'r') as f:
        content = f.read()

    # Remove all multiline includes with 'with'
    content = re.sub(
        r'{%\s*include\s+"[^"]+"\s+with[\s\S]*?%}',
        lambda m: '{% include "' + re.search(r'include\s+"([^"]+)"', m.group(0)).group(1) + '" %}',
        content
    )

    with open(filepath, 'w') as f:
        f.write(content)
    print(f"✓ Fixed: {filepath}")

def main():
    """Fix the three problematic files."""
    print("=" * 60)
    print("Fixing remaining Tera template errors")
    print("=" * 60)

    files_to_fix = {
        "orders/index.html": fix_orders_index,
        "orders/show.html": fix_orders_show,
        "listings/show.html": fix_listings_show,
    }

    for rel_path, fix_func in files_to_fix.items():
        filepath = TEMPLATES_DIR / rel_path
        if filepath.exists():
            fix_func(filepath)
        else:
            print(f"✗ File not found: {filepath}")

    print("=" * 60)
    print("Done")
    print("=" * 60)

if __name__ == "__main__":
    main()
