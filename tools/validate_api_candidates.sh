#!/bin/bash
# Validate API leak/doc candidates - filter out non-API document URLs
# SAFE VERSION: Creates .validated file, preserves original for manual review

INPUT="$1"
OUTPUT="$2"

if [[ -z "$INPUT" || -z "$OUTPUT" ]]; then
    echo "Usage: $0 <input_file> <output_file>"
    echo "Note: Creates INPUT.validated if OUTPUT == INPUT to preserve original"
    exit 1
fi

# If output == input, create .validated version to preserve original
if [[ "$INPUT" == "$OUTPUT" ]]; then
    OUTPUT="${INPUT}.validated"
    PRESERVE_ORIGINAL=true
else
    PRESERVE_ORIGINAL=false
fi

# Only keep URLs that match real API doc patterns:
# - End with .json, .yaml, .yml
# - Contain swagger, openapi, /api-docs, /v[0-9]/docs, postman, wadl
# - Exclude common document extensions (.doc, .pdf, .ppt, .xls)

grep -iE '(swagger|openapi|/api-docs|/v[0-9]/docs|postman|\.json$|\.yaml$|\.yml$|wadl|raml)' "$INPUT" \
    | grep -viE '\.(doc|docx|pdf|ppt|pptx|xls|xlsx)(\?|$|&)' \
    > "$OUTPUT"

BEFORE=$(wc -l < "$INPUT" 2>/dev/null || echo 0)
AFTER=$(wc -l < "$OUTPUT" 2>/dev/null || echo 0)
REMOVED=$((BEFORE - AFTER))

echo "API candidate validation:"
echo "  Original: $BEFORE"
echo "  Validated: $AFTER"
echo "  Filtered: $REMOVED (non-API documents)"

if [[ "$PRESERVE_ORIGINAL" == "true" ]]; then
    echo "  Note: Original preserved at $INPUT, validated at $OUTPUT"
fi
