#!/bin/bash
# Create the system arbiter account
# This account is auto-assigned to all escrows when a counterparty joins

BASE_URL="http://127.0.0.1:8080"
ARBITER_USERNAME="system_arbiter"
ARBITER_PASSWORD="${1:-ArbiterSecure2026!}"

echo "Creating arbiter account: $ARBITER_USERNAME"
echo "Password: ${ARBITER_PASSWORD:0:4}****"
echo ""

RESPONSE=$(curl -s -X POST "$BASE_URL/api/auth/register-json" \
  -H "Content-Type: application/json" \
  -d "{
    \"username\": \"$ARBITER_USERNAME\",
    \"password\": \"$ARBITER_PASSWORD\",
    \"role\": \"arbiter\"
  }" 2>/dev/null)

echo "Response: $RESPONSE"

if echo "$RESPONSE" | grep -q '"success":true\|"id"'; then
  echo ""
  echo "Arbiter account created successfully."
  echo "Login with: $ARBITER_USERNAME / $ARBITER_PASSWORD"
  echo ""
  echo "This account will be auto-assigned as arbiter for all new escrows."
elif echo "$RESPONSE" | grep -q "already exists\|Username taken"; then
  echo ""
  echo "Arbiter account already exists. You can login with it directly."
else
  echo ""
  echo "Registration may have failed. Check the response above."
  echo "Common issues:"
  echo "  - Password too weak (needs uppercase, lowercase, number, special char, 8+ chars)"
  echo "  - Server not running"
fi
