#!/usr/bin/env bash
# Post an article to DEV.to from a markdown file
# Usage: DEV_API_KEY=your_key ./devto_post.sh github_botnet_discovery_revised.md
# Get your API key: https://dev.to/settings/extensions -> DEV API Keys

set -euo pipefail

if [[ -z "${DEV_API_KEY:-}" ]]; then
  echo "Error: DEV_API_KEY not set"
  echo "Usage: DEV_API_KEY=your_key ./devto_post.sh <file.md>"
  exit 1
fi

MD_FILE="${1:-}"
if [[ -z "$MD_FILE" || ! -f "$MD_FILE" ]]; then
  echo "Error: markdown file not found: $MD_FILE"
  exit 1
fi

# Strip front matter, pass body_markdown as the full file content
# DEV.to API reads front matter fields (title, tags, etc.) out of body_markdown directly
BODY=$(cat "$MD_FILE")

# Escape for JSON — handles quotes, newlines, backslashes
ESCAPED=$(python3 -c "
import sys, json
content = open(sys.argv[1]).read()
print(json.dumps(content))
" "$MD_FILE")

PAYLOAD=$(cat <<EOF
{
  "article": {
    "body_markdown": $ESCAPED
  }
}
EOF
)

echo "Posting to DEV.to..."

RESPONSE=$(curl -s -w "\n%{http_code}" \
  -X POST https://dev.to/api/articles \
  -H "Content-Type: application/json" \
  -H "api-key: ${DEV_API_KEY}" \
  -d "$PAYLOAD")

HTTP_BODY=$(echo "$RESPONSE" | head -n -1)
HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)

if [[ "$HTTP_CODE" == "201" ]]; then
  URL=$(echo "$HTTP_BODY" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('url','(no url)'))")
  ID=$(echo "$HTTP_BODY"  | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('id','(no id)'))")
  echo "Posted successfully (id: $ID)"
  echo "URL: $URL"
else
  echo "Error: HTTP $HTTP_CODE"
  echo "$HTTP_BODY"
  exit 1
fi
