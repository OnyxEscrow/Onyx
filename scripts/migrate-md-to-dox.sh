#!/bin/bash

# Migration script: Move all Markdown files to DOX/ folder
# Preserves critical files (CLAUDE.md, README.md) at root
# Creates logical folder structure

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}=== Markdown Files Migration to DOX/ ===${NC}\n"

# Create DOX structure
echo -e "${YELLOW}Creating DOX folder structure...${NC}"
mkdir -p DOX/{protocols,guides,sessions,phases,reports,audits,migration,testing,frontend}

# Files to KEEP at root (critical for scripts)
KEEP_AT_ROOT=(
    "CLAUDE.md"
    "README.md"
)

# Define categories for organization
declare -A FILE_CATEGORIES

# Protocols
FILE_CATEGORIES["PROTOCOLE-ALPHA-TERMINAL.md"]="protocols"
FILE_CATEGORIES["PROTOCOLE-BETA-TERMINAL.md"]="protocols"
FILE_CATEGORIES["PROTOCOLE-BETA-TERMINAL-FRONTEND-v2.md"]="protocols"

# Guides
FILE_CATEGORIES["DEMARRAGE_RAPIDE.md"]="guides"
FILE_CATEGORIES["QUICK-START-UBUNTU.md"]="guides"
FILE_CATEGORIES["QUICK-START-REPUTATION.md"]="guides"
FILE_CATEGORIES["GUIDE-TEST-MANUEL.md"]="guides"
FILE_CATEGORIES["GEMINI-SKILL-GUIDE.md"]="guides"
FILE_CATEGORIES["MIGRATION-UBUNTU.md"]="guides"
FILE_CATEGORIES["MIGRATION-WSL2.md"]="guides"
FILE_CATEGORIES["UBUNTU-SETUP.md"]="guides"
FILE_CATEGORIES["WINDOWS-TO-LINUX.md"]="guides"
FILE_CATEGORIES["commande.md"]="guides"
FILE_CATEGORIES["COMMANDES_UBUNTU.md"]="guides"
FILE_CATEGORIES["guidtechnique.md"]="guides"

# Session reports
FILE_CATEGORIES["SESSION-SUMMARY.md"]="sessions"
FILE_CATEGORIES["SUMMARY-SESSION.md"]="sessions"
FILE_CATEGORIES["SESSION-RECAP-REP3-4.md"]="sessions"

# Phase documentation
FILE_CATEGORIES["PHASE-1-CHECKLIST.md"]="phases"
FILE_CATEGORIES["PHASE-3-4-PRAGMATIC-APPROACH.md"]="phases"
FILE_CATEGORIES["PHASE-5-PLAN.md"]="phases"
FILE_CATEGORIES["PHASE-5-RESULTS.md"]="phases"
FILE_CATEGORIES["PLAN-PHASE-4-FRONTEND.md"]="phases"
FILE_CATEGORIES["PLAN-COMPLET.md"]="phases"

# Reports (Alpha/Beta terminal outputs, completions)
FILE_CATEGORIES["ALPHA-TERMINAL-NON-CUSTODIAL-2025-10-23.md"]="reports"
FILE_CATEGORIES["BETA-TERMINAL-NON-CUSTODIAL-REPORT-2025-10-23.md"]="reports"
FILE_CATEGORIES["BETA-TERMINAL-REPUTATION-COMPLETE-2025-10-23.md"]="reports"
FILE_CATEGORIES["BETA-TERMINAL-REPUTATION-REPORT.md"]="reports"
FILE_CATEGORIES["BETA-TERMINAL-REPORT-SESSION2.md"]="reports"
FILE_CATEGORIES["BETA-TERMINAL-FRONTEND-REPORT.md"]="reports"
FILE_CATEGORIES["COMPLETION-REP-3-4.md"]="reports"
FILE_CATEGORIES["SUCCESS-REP3-4-INTEGRATION.md"]="reports"
FILE_CATEGORIES["NON-CUSTODIAL-PHASE-2-COMPLETE-2025-10-23.md"]="reports"
FILE_CATEGORIES["NON-CUSTODIAL-AUDIT-COMPLETE-2025-10-23.md"]="reports"
FILE_CATEGORIES["NON-CUSTODIAL-MIGRATION-COMPLETE.md"]="reports"
FILE_CATEGORIES["NON-CUSTODIAL-CERTIFICATION.md"]="reports"
FILE_CATEGORIES["NON-CUSTODIAL-ANALYSIS-2025-10-23.md"]="reports"
FILE_CATEGORIES["ULTRA-AUTOMATION-PHASE-1-COMPLETE.md"]="reports"
FILE_CATEGORIES["IMPLEMENTATION_COMPLETE.md"]="reports"
FILE_CATEGORIES["CLIPPY_REPORT.md"]="reports"

# Audits
FILE_CATEGORIES["AUDIT-V3.md"]="audits"
FILE_CATEGORIES["ANTI-SECURITY-THEATRE-IMPLEMENTATION.md"]="audits"
FILE_CATEGORIES["CORRECTION-SCORES.md"]="audits"
FILE_CATEGORIES["SECURITY_VALIDATION.md"]="audits"

# Migration documentation
FILE_CATEGORIES["DESIGN-MIGRATION.md"]="migration"
FILE_CATEGORIES["DESIGN-MIGRATION-PROGRESS.md"]="migration"
FILE_CATEGORIES["CUSTODIAL-MODULE-ORGANIZED-2025-10-23.md"]="migration"
FILE_CATEGORIES["CUSTODIAL-MODULE-DEVELOPMENT-STARTED-2025-10-23.md"]="migration"
FILE_CATEGORIES["FRONTEND-STYLE-RESTORED-2025-10-23.md"]="migration"
FILE_CATEGORIES["FRONTEND-FIX-2025-10-23.md"]="migration"
FILE_CATEGORIES["REFACTORING_SUMMARY.md"]="migration"
FILE_CATEGORIES["RESTRUCTURE_PROPOSAL.md"]="migration"

# Testing
FILE_CATEGORIES["DEV_TESTING.md"]="testing"
FILE_CATEGORIES["TEST_FLOW_GUIDE.md"]="testing"
FILE_CATEGORIES["BUG_SHIPPED_ORDER.md"]="testing"

# Frontend
FILE_CATEGORIES["corrected_torrc.md"]="frontend"

# Status/State files
FILE_CATEGORIES["ETAT-FLOW-MARKETPLACE.md"]="reports"
FILE_CATEGORIES["etatglobal.md"]="reports"
FILE_CATEGORIES["FICHIERS_MODIFIES.md"]="reports"
FILE_CATEGORIES["FICHIERS_AUTH.md"]="reports"

# Implementation files
FILE_CATEGORIES["FIXES-APPLIED.md"]="reports"
FILE_CATEGORIES["PRODUCTION-READY-FIXES.md"]="reports"
FILE_CATEGORIES["PRODUCTION-READY-PLAN.md"]="phases"
FILE_CATEGORIES["HEALTHCHECKS-ADDED.md"]="reports"
FILE_CATEGORIES["IMAGE-UPLOAD-SYSTEM.md"]="reports"
FILE_CATEGORIES["REPUTATION-INTEGRATION.md"]="reports"
FILE_CATEGORIES["TIMEOUT_IMPLEMENTATION.md"]="reports"

# Milestones
FILE_CATEGORIES["MILESTONE-2.3-VERIFICATION.md"]="phases"

# Instructions
FILE_CATEGORIES["INSTRUCTIONS-GEMINI-PHASE-4.5.md"]="guides"
FILE_CATEGORIES["INSTRUCTIONS-GEMINI-REPUTATION.md"]="guides"
FILE_CATEGORIES["TACHES-IMMEDIATES.md"]="guides"

# Gemini/AI
FILE_CATEGORIES["GEMINI.md"]="guides"
FILE_CATEGORIES["GEMINI-SKILL-INSTALLED.md"]="guides"

# Announcements
FILE_CATEGORIES["ANNOUNCEMENT.md"]="reports"

# Move files
moved=0
kept=0
errors=0

for file in *.md; do
    # Skip if file doesn't exist (glob didn't match)
    [[ ! -f "$file" ]] && continue

    # Check if file should stay at root
    should_keep=0
    for keep_file in "${KEEP_AT_ROOT[@]}"; do
        if [[ "$file" == "$keep_file" ]]; then
            should_keep=1
            echo -e "${GREEN}✓${NC} Keeping at root: ${file}"
            ((kept++))
            break
        fi
    done

    [[ $should_keep -eq 1 ]] && continue

    # Determine destination
    if [[ -n "${FILE_CATEGORIES[$file]}" ]]; then
        dest="DOX/${FILE_CATEGORIES[$file]}/$file"
    else
        # Default: reports
        dest="DOX/reports/$file"
    fi

    # Move file
    if mv "$file" "$dest" 2>/dev/null; then
        echo -e "${BLUE}→${NC} Moved: ${file} → ${dest}"
        ((moved++))
    else
        echo -e "${YELLOW}⚠${NC} Error moving: ${file}"
        ((errors++))
    fi
done

echo ""
echo -e "${GREEN}=== Migration Complete ===${NC}"
echo -e "Files moved: ${BLUE}${moved}${NC}"
echo -e "Files kept at root: ${GREEN}${kept}${NC}"
echo -e "Errors: ${YELLOW}${errors}${NC}"

echo ""
echo -e "${YELLOW}Next steps:${NC}"
echo "1. Update script references (if any)"
echo "2. Test critical scripts: ./scripts/check-environment.sh"
echo "3. Update any .gitignore patterns if needed"
