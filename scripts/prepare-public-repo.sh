#!/bin/bash
# Prepare a clean public repository for open-source release.
# Uses a whitelist approach: only includes essential source code and documentation.
set -euo pipefail

DEST="${1:-/home/malix/Desktop/onyx-escrow-public}"

if [ -d "$DEST" ]; then
    echo "ERROR: $DEST already exists. Remove it first or choose a different path."
    exit 1
fi

echo "Creating clean public repo at: $DEST"
mkdir -p "$DEST"

SRC="/home/malix/Desktop/NEXUS"

# ─── Whitelist copy ───────────────────────────────────────────────
# Core Rust crates
for dir in common cli server wallet nexus-crypto-core nexus-types; do
    if [ -d "$SRC/$dir" ]; then
        rsync -a --exclude='target' --exclude='*.db' --exclude='*.sqlite' "$SRC/$dir/" "$DEST/$dir/"
    fi
done

# Frontend
rsync -a "$SRC/nexusfinalappdsn/" "$DEST/nexusfinalappdsn/"

# SDKs
rsync -a --exclude='node_modules' --exclude='dist' --exclude='__pycache__' \
    --exclude='.coverage' --exclude='*.egg-info' \
    "$SRC/packages/" "$DEST/packages/"

# Migrations
if [ -d "$SRC/migrations" ]; then
    rsync -a "$SRC/migrations/" "$DEST/migrations/"
fi

# Static assets (WASM builds, etc.)
if [ -d "$SRC/static" ]; then
    rsync -a "$SRC/static/" "$DEST/static/"
fi

# Templates
if [ -d "$SRC/templates" ]; then
    rsync -a "$SRC/templates/" "$DEST/templates/"
fi

# Scripts (minus ai/ directory)
rsync -a --exclude='ai' "$SRC/scripts/" "$DEST/scripts/"

# GitHub workflows (minus claude-*.yml)
mkdir -p "$DEST/.github/workflows"
for f in "$SRC/.github/workflows/"*.yml; do
    fname=$(basename "$f")
    if [[ "$fname" != claude-* ]]; then
        cp "$f" "$DEST/.github/workflows/$fname"
    fi
done

# Top-level files
for f in README.md PROTOCOL.md Cargo.toml diesel.toml .gitignore .env.example .cargo; do
    if [ -e "$SRC/$f" ]; then
        cp -r "$SRC/$f" "$DEST/$f"
    fi
done

# Create LICENSE if it doesn't exist
if [ ! -f "$DEST/LICENSE" ]; then
    cat > "$DEST/LICENSE" << 'LICEOF'
MIT License

Copyright (c) 2025-2026 Onyx-Escrow Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
LICEOF
fi

# ─── Verification sweep ──────────────────────────────────────────
echo ""
echo "=== AI MENTION SWEEP ==="
AI_HITS=$(grep -ri "claude\|anthropic\|co-authored-by\|AI-generated\|AI-assisted\|vibe.cod\|copilot" \
    --include="*.md" --include="*.rs" --include="*.ts" --include="*.tsx" \
    --include="*.py" --include="*.toml" --include="*.json" --include="*.yml" \
    "$DEST" 2>/dev/null | grep -v "node_modules" | grep -v ".cargo" || true)

if [ -n "$AI_HITS" ]; then
    echo "WARNING: Found AI mentions that need cleanup:"
    echo "$AI_HITS"
    echo ""
    echo "Fix these before committing!"
else
    echo "CLEAN: No AI mentions found."
fi

echo ""
echo "=== SECRETS SWEEP ==="
SECRET_HITS=$(grep -ri "nxs_f9164\|168\.222\|incognet\|TROCADOR\|ARBITER_VAULT\|DB_ENCRYPTION_KEY=\|0dd5961f" \
    --include="*.py" --include="*.rs" --include="*.yml" --include="*.md" \
    --include="*.env*" --include="*.toml" --include="*.json" \
    "$DEST" 2>/dev/null || true)

if [ -n "$SECRET_HITS" ]; then
    echo "WARNING: Found potential secrets:"
    echo "$SECRET_HITS"
    echo ""
    echo "Fix these before committing!"
else
    echo "CLEAN: No secrets found."
fi

echo ""
echo "=== STATS ==="
echo "Files: $(find "$DEST" -type f | wc -l)"
echo "Size: $(du -sh "$DEST" | cut -f1)"
echo ""
echo "Done. Review $DEST, then:"
echo "  cd $DEST"
echo "  git init && git add -A"
echo "  git commit -m 'Initial release: FROST threshold escrow for Monero'"
