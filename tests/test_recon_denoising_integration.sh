#!/bin/bash
# Test recon_engine.sh denoising integration

echo "════════════════════════════════════════════════════════════"
echo "  Recon Engine Denoising Integration - Test"
echo "════════════════════════════════════════════════════════════"
echo ""

# Check integration points
echo "✓ Checking integration points..."
echo ""

echo "1. Phase 4.5 (URL Denoising):"
if grep -q "Phase 4.5: URL Denoising" tools/recon_engine.sh; then
    echo "   ✅ Found Phase 4.5"
    grep -n "Phase 4.5" tools/recon_engine.sh | head -1

    # Check if recon_filters.py is called non-destructively.
    if grep -q 'python3 "$BASE_DIR/tools/recon_filters.py"' tools/recon_engine.sh; then
        echo "   ✅ recon_filters.py integration found"
    else
        echo "   ❌ recon_filters.py not called"
    fi

    if grep -q "all_filtered.txt" tools/recon_engine.sh && grep -q -- "--log-file" tools/recon_engine.sh; then
        echo "   ✅ non-destructive filtered artifacts + filter.log found"
    else
        echo "   ❌ non-destructive filtered artifacts/log missing"
    fi

    if grep -q '"$RECON_DIR/urls/${url_file}.txt"' tools/recon_engine.sh; then
        echo "   ❌ in-place URL filtering pattern still present"
    else
        echo "   ✅ raw URL files are not filtered in-place"
    fi
else
    echo "   ❌ Phase 4.5 not found"
fi

echo ""
echo "2. Phase 6.7.5 (API Candidate Validation):"
if grep -q "Phase 6.7.5: API Candidate Validation" tools/recon_engine.sh; then
    echo "   ✅ Found Phase 6.7.5"
    grep -n "Phase 6.7.5" tools/recon_engine.sh | head -1

    # Check if validate_api_candidates.sh is called
    if grep -q "bash tools/validate_api_candidates.sh" tools/recon_engine.sh; then
        echo "   ✅ validate_api_candidates.sh integration found"
    else
        echo "   ❌ validate_api_candidates.sh not called"
    fi
else
    echo "   ❌ Phase 6.7.5 not found"
fi

echo ""
echo "3. Tools availability:"
if [ -f "tools/recon_filters.py" ]; then
    echo "   ✅ tools/recon_filters.py exists"
    ls -lh tools/recon_filters.py
else
    echo "   ❌ tools/recon_filters.py not found"
fi

if [ -f "tools/validate_api_candidates.sh" ]; then
    echo "   ✅ tools/validate_api_candidates.sh exists"
    ls -lh tools/validate_api_candidates.sh
else
    echo "   ❌ tools/validate_api_candidates.sh not found"
fi

echo ""
echo "════════════════════════════════════════════════════════════"
echo "  Integration Summary"
echo "════════════════════════════════════════════════════════════"
echo ""

PHASE_45=$(grep -c "Phase 4.5: URL Denoising" tools/recon_engine.sh)
PHASE_675=$(grep -c "Phase 6.7.5: API Candidate Validation" tools/recon_engine.sh)
FILTER_CALLS=$(grep -c 'python3 "$BASE_DIR/tools/recon_filters.py"' tools/recon_engine.sh)
VALIDATE_CALLS=$(grep -c "bash tools/validate_api_candidates.sh" tools/recon_engine.sh)

echo "Integration points:"
echo "  • Phase 4.5 declarations: $PHASE_45"
echo "  • Phase 6.7.5 declarations: $PHASE_675"
echo "  • recon_filters.py calls: $FILTER_CALLS"
echo "  • validate_api_candidates.sh calls: $VALIDATE_CALLS"
echo ""

if [[ $PHASE_45 -ge 1 ]] && [[ $PHASE_675 -ge 1 ]] && [[ $FILTER_CALLS -ge 1 ]] && [[ $VALIDATE_CALLS -ge 1 ]]; then
    echo "Status: ✅ Integration SUCCESSFUL"
    echo ""
    echo "Next steps:"
    echo "  1. Test on a small target: bash tools/recon_engine.sh -t test.com"
    echo "  2. Check logs: recon/test.com/urls/filter.log"
    echo "  3. Verify raw all.txt is preserved and all_filtered.txt is generated"
else
    echo "Status: ❌ Integration INCOMPLETE"
    echo ""
    echo "Missing components:"
    [[ $PHASE_45 -eq 0 ]] && echo "  - Phase 4.5 declaration"
    [[ $PHASE_675 -eq 0 ]] && echo "  - Phase 6.7.5 declaration"
    [[ $FILTER_CALLS -eq 0 ]] && echo "  - recon_filters.py calls"
    [[ $VALIDATE_CALLS -eq 0 ]] && echo "  - validate_api_candidates.sh calls"
fi

echo ""
echo "════════════════════════════════════════════════════════════"
