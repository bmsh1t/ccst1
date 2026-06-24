#!/bin/bash
# CORS Misconfiguration Validator for chinaaid.org
# Target: https://pay.chinaaid.org

TARGET="https://pay.chinaaid.org"
EVIL_ORIGIN="https://attacker-controlled.com"

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "CORS Misconfiguration Validator"
echo "Target: $TARGET"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo

echo "[1] Testing arbitrary origin reflection..."
echo "Origin: $EVIL_ORIGIN"
echo

RESPONSE=$(curl -s -I -H "Origin: $EVIL_ORIGIN" "$TARGET" 2>&1)

echo "$RESPONSE"
echo

# Check for vulnerable patterns
ACAO=$(echo "$RESPONSE" | grep -i "access-control-allow-origin" | cut -d: -f2- | tr -d ' \r\n')
ACAC=$(echo "$RESPONSE" | grep -i "access-control-allow-credentials" | cut -d: -f2- | tr -d ' \r\n')

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Analysis:"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [[ -n "$ACAO" ]]; then
    echo "✓ Access-Control-Allow-Origin: $ACAO"

    if [[ "$ACAO" == "$EVIL_ORIGIN" ]] || [[ "$ACAO" == "*" ]]; then
        echo "  ⚠️  VULNERABLE: Arbitrary origin reflected!"

        if [[ -n "$ACAC" ]] && [[ "$ACAC" == "true" ]]; then
            echo "✓ Access-Control-Allow-Credentials: true"
            echo "  ⚠️  CRITICAL: Credentials allowed with arbitrary origin!"
            echo "  🎯 Exploitable: Can steal authenticated user data"
        else
            echo "✗ Access-Control-Allow-Credentials: false or missing"
            echo "  Impact: Limited to public data theft"
        fi
    else
        echo "  ℹ️  Origin not reflected (whitelist in place)"
    fi
else
    echo "✗ No CORS headers found"
fi

echo
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[2] Testing common API endpoints..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo

# Test common API paths
API_PATHS=(
    "/api/user"
    "/api/payment"
    "/api/donation"
    "/api/account"
    "/api/profile"
    "/user/info"
    "/account/details"
)

for path in "${API_PATHS[@]}"; do
    echo -n "Testing $TARGET$path ... "
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" -H "Origin: $EVIL_ORIGIN" "$TARGET$path" 2>/dev/null)

    if [[ "$STATUS" == "200" ]] || [[ "$STATUS" == "403" ]] || [[ "$STATUS" == "401" ]]; then
        echo "[$STATUS] - Exists, checking CORS..."
        ACAO_API=$(curl -s -I -H "Origin: $EVIL_ORIGIN" "$TARGET$path" 2>/dev/null | grep -i "access-control-allow-origin" | cut -d: -f2- | tr -d ' \r\n')
        if [[ -n "$ACAO_API" ]]; then
            echo "  → CORS enabled: $ACAO_API"
        fi
    else
        echo "[$STATUS] - Not found"
    fi
done

echo
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Validation Complete"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
