#!/usr/bin/env bash
set -euo pipefail

# Requires WAZUH_API_PASSWORD to be set in the environment (from a GitHub secret).
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RULES_FILE="$REPO_DIR/converter/output/sentryforge_rules.xml"

if [ -z "${WAZUH_API_PASSWORD:-}" ]; then
  echo "ERROR: WAZUH_API_PASSWORD is not set." >&2
  exit 1
fi

if [ ! -f "$RULES_FILE" ]; then
  echo "ERROR: $RULES_FILE not found. Run the converter first." >&2
  exit 1
fi

echo "Authenticating to Wazuh API..."
TOKEN=$(curl -sk -u "wazuh-wui:${WAZUH_API_PASSWORD}" -X POST "https://localhost:55000/security/user/authenticate?raw=true")

if [ -z "$TOKEN" ]; then
  echo "ERROR: Failed to obtain API token." >&2
  exit 1
fi

echo "Uploading rules file..."
UPLOAD_RESPONSE=$(curl -sk -X PUT "https://localhost:55000/rules/files/sentryforge_rules.xml?overwrite=true" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/octet-stream" \
  --data-binary "@$RULES_FILE")
echo "$UPLOAD_RESPONSE"

if ! echo "$UPLOAD_RESPONSE" | grep -q '"error": 0'; then
  echo "ERROR: Rule upload failed." >&2
  exit 1
fi

echo "Restarting Wazuh manager..."
curl -sk -X PUT "https://localhost:55000/manager/restart" -H "Authorization: Bearer $TOKEN"
echo ""
echo "Waiting for manager to come back up..."
MAX_WAIT=90
WAITED=0
until systemctl is-active --quiet wazuh-manager; do
  if [ "$WAITED" -ge "$MAX_WAIT" ]; then
    echo "ERROR: wazuh-manager did not become active within ${MAX_WAIT}s." >&2
    systemctl status wazuh-manager --no-pager || true
    exit 1
  fi
  sleep 5
  WAITED=$((WAITED + 5))
  echo "  ...still waiting (${WAITED}s elapsed)"
done

echo "wazuh-manager is active after ${WAITED}s."

# Confirm our rule is actually loaded, not just that the service is up.
sleep 3
if sudo -n /var/ossec/bin/wazuh-analysisd -t; then
  echo "Ruleset validated clean."
else
  echo "ERROR: wazuh-analysisd config test failed after restart." >&2
  exit 1
fi

echo "Deploy successful."
