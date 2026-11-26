#!/bin/bash
set -euo pipefail
# fetch the OIDC thumbprint for the region's endpoint
THUMB=$(echo | openssl s_client -servername "oidc.eks.$1.amazonaws.com" -showcerts -connect "oidc.eks.$1.amazonaws.com:443" 2>/dev/null \
  | openssl x509 -fingerprint -sha1 -noout | cut -d= -f2 | tr -d ':')
ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
jq -n --arg t "$THUMB" --arg a "$ACCOUNT" '{"thumbprint":$t,"account":$a}'
