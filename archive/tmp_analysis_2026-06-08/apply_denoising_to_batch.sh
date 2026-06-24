#!/bin/bash
# Apply denoising to all mb1.txt targets

TARGETS=(
    "ohchr.org"
    "dfc.gov"
    "ifw-kiel.de"
    "kielinstitut.de"
    "baronpa.com"
)

for target in "${TARGETS[@]}"; do
    echo "========================================"
    echo "Processing: $target"
    echo "========================================"
    
    # Check if recon exists
    if [[ ! -d "recon/$target" ]]; then
        echo "  ⚠️  No recon found, skipping"
        continue
    fi
    
    # Backup
    if [[ ! -d "recon/${target}.backup" ]]; then
        echo "  [1/5] Backing up..."
        cp -r "recon/$target" "recon/${target}.backup"
    else
        echo "  [1/5] Backup exists, skipping"
    fi
    
    # Filter URL files
    echo "  [2/5] Filtering URL files..."
    for file in all with_params katana gau waymore; do
        if [[ -f "recon/$target/urls/${file}.txt" ]]; then
            python3 tools/recon_filters.py \
                "recon/$target/urls/${file}.txt" \
                "recon/$target/urls/${file}.txt" \
                "$target" 2>&1 | grep -E "Filtering complete|Removed|Kept"
        fi
    done
    
    # Validate API candidates
    echo "  [3/5] Validating API candidates..."
    if [[ -f "recon/$target/exposure/api_leak_candidates.txt" ]]; then
        bash tools/validate_api_candidates.sh \
            "recon/$target/exposure/api_leak_candidates.txt" \
            "recon/$target/exposure/api_leak_candidates.txt" 2>&1 | grep -v "^$"
    fi
    
    # Regenerate api_endpoints.txt
    echo "  [4/5] Regenerating api_endpoints.txt..."
    if [[ -f "recon/$target/urls/all.txt" ]]; then
        grep -iE '/api/|/v[0-9]+/|graphql|/rest/' \
            "recon/$target/urls/all.txt" \
            > "recon/$target/urls/api_endpoints.txt"
        echo "    Generated: $(wc -l < "recon/$target/urls/api_endpoints.txt") endpoints"
    fi
    
    # Re-run surface
    echo "  [5/5] Re-running surface.py..."
    python3 tools/surface.py --target "$target" 2>&1 | head -30 | grep -E "Priority 1|^[0-9]\.|Score:|Total candidates"
    
    echo ""
done

echo "========================================"
echo "Batch denoising complete!"
echo "========================================"
