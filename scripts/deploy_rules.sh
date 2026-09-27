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
sleep 20

if ! systemctl is-active --quiet wazuh-manager; then
  echo "ERROR: wazuh-manager is not active after restart." >&2
  exit 1
fi

echo "Deploy successful. wazuh-manager is active."
