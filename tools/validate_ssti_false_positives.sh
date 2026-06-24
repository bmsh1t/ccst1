#!/bin/bash
# SSTI False Positive Validator
# Tests if template syntax in URL parameters is evaluated server-side

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "SSTI False Positive Validator"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo

# Test targets
declare -A TARGETS=(
    ["article19"]="https://www.article19.org/wp-content/themes/article19/assets/js/main.js?ver={{7*7}}"
    ["ifw-kiel"]="https://greix-cloud.ifw-kiel.de/dist/core-main.js?v={{7*7}}"
)

for name in "${!TARGETS[@]}"; do
    url="${TARGETS[$name]}"
    echo "[Testing] $name"
    echo "URL: $url"
    echo

    # Fetch response
    response=$(curl -s "$url" 2>&1)
    status=$?

    if [[ $status -ne 0 ]]; then
        echo "  ✗ Connection failed"
        echo
        continue
    fi

    # Check if it's JavaScript
    if echo "$response" | head -20 | grep -qi "function\|var\|const\|document"; then
        echo "  ✓ Response contains JavaScript code"
    else
        echo "  ? Response doesn't look like JS"
    fi

    # Check for template syntax in response
    if echo "$response" | grep -F "{{7*7}}" > /dev/null 2>&1; then
        echo "  ⚠️  Template syntax REFLECTED in response"
        echo "  → Potential SSTI (requires further testing)"
    elif echo "$response" | grep -E "\b49\b" > /dev/null 2>&1; then
        echo "  ⚠️  Evaluated result (49) found in response"
        echo "  → Potential SSTI confirmed"
    else
        echo "  ✓ No template syntax or evaluation in response"
        echo "  → FALSE POSITIVE confirmed (static asset)"
    fi

    echo
done

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Validation Complete"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
