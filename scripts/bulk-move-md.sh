#!/bin/bash

# Bulk move all markdown files to DOX (except CLAUDE.md and README.md)

cd /home/malix/Desktop/monero.marketplace

for file in *.md; do
  # Skip if not a file
  [[ ! -f "$file" ]] && continue

  # Skip critical files
  [[ "$file" == "CLAUDE.md" ]] && continue
  [[ "$file" == "README.md" ]] && continue

  # Determine destination
  case "$file" in
    PROTOCOLE*.md)
      dest="DOX/protocols/$file" ;;
    *GUIDE*.md|*QUICK-START*.md|DEMARRAGE*.md|*UBUNTU*.md|*MIGRATION*.md|commande.md|COMMANDES*.md|guidtechnique.md|GEMINI*.md|INSTRUCTIONS*.md|TACHES*.md)
      dest="DOX/guides/$file" ;;
    *SESSION*.md|*SUMMARY*.md)
      dest="DOX/sessions/$file" ;;
    PHASE*.md|PLAN*.md|ROADMAP.md)
      dest="DOX/phases/$file" ;;
    *TERMINAL*.md|*COMPLETE*.md|*REPORT*.md|COMPLETION*.md|*SUCCESS*.md|CLIPPY*.md|ETAT*.md|etatglobal.md|FICHIERS*.md|FIXES*.md|*READY*.md|HEALTHCHECK*.md|IMAGE*.md|REPUTATION*.md|TIMEOUT*.md|ANNOUNCEMENT*.md|STATUS*.md|STAGING*.md|START*.md|RUST*.md)
      dest="DOX/reports/$file" ;;
    *AUDIT*.md|ANTI-SECURITY*.md|CORRECTION*.md|SECURITY*.md)
      dest="DOX/audits/$file" ;;
    DESIGN*.md|CUSTODIAL*.md|FRONTEND*.md|REFACTORING*.md|RESTRUCTURE*.md|NON-CUSTODIAL*.md)
      dest="DOX/migration/$file" ;;
    *TEST*.md|BUG*.md|DEV_*.md)
      dest="DOX/testing/$file" ;;
    corrected_torrc.md|NEXUS*.md|TERA*.md|simple.md|TAF.md)
      dest="DOX/frontend/$file" ;;
    *)
      dest="DOX/reports/$file" ;;
  esac

  # Move file
  mkdir -p "$(dirname "$dest")"
  if mv "$file" "$dest" 2>/dev/null; then
    echo "✓ $file → $dest"
  fi
done

echo ""
echo "Migration complete!"
echo "Files at root:"
ls -1 *.md 2>/dev/null | wc -l
echo "Files in DOX:"
find DOX -name "*.md" | wc -l
