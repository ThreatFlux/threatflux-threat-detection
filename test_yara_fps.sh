#!/bin/bash

# YARA Rule FPS (False Positive) Testing Script
# Tests generated YARA rules against known clean files

echo "=== YARA Rule False Positive Testing ==="
echo "Generated: $(date)"
echo ""

YARA_RULES="yara_rules_generated.yar"
TEST_DIR="/media/vtriple/A8E8E234E8E20084"

# Test 1: Specific file matches (should match)
echo "=== Test 1: Expected Matches ==="
echo "Testing rules against the original analyzed files..."

echo "1. Testing AMD PPM Service:"
yara -w $YARA_RULES "$TEST_DIR/AMD/Chipset_Software/Binaries/PPM Provisioning File Driver/WTx64/AmdPpkgSvc.exe" 2>/dev/null || echo "  No match (expected match)"

echo "2. Testing AMD TEE API:"
yara -w $YARA_RULES "$TEST_DIR/AMD/Chipset_Software/Binaries/PSP Driver/WTx64/amdtee_api64.dll" 2>/dev/null || echo "  No match (expected match)"

echo "3. Testing AMD Qt Setup:"
yara -w $YARA_RULES "$TEST_DIR/AMD/RyzenMasterExtract/MSIFiles/Qt_Dependancies/Setup.exe" 2>/dev/null || echo "  No match (expected match)"

echo ""

# Test 2: Random Windows system files (should not match specific rules)
echo "=== Test 2: False Positive Check - Windows System Files ==="
echo "Testing against common Windows files that should NOT match specific rules..."

# Test against Windows system files if they exist
SYSTEM_FILES=(
    "/usr/bin/ls"
    "/usr/bin/cat" 
    "/usr/bin/grep"
    "/usr/bin/find"
    "/bin/bash"
)

for file in "${SYSTEM_FILES[@]}"; do
    if [[ -f "$file" ]]; then
        echo "Testing: $file"
        result=$(yara -w $YARA_RULES "$file" 2>/dev/null)
        if [[ -n "$result" ]]; then
            echo "  ⚠️  FALSE POSITIVE: $result"
        else
            echo "  ✅ Clean (no match)"
        fi
    fi
done

echo ""

# Test 3: Random AMD files (may trigger generic rule)
echo "=== Test 3: AMD Generic Rule Testing ==="
echo "Testing generic AMD rule against other AMD files..."

# Find a few more AMD files to test
mapfile -t AMD_FILES < <(find "$TEST_DIR" -name "*AMD*" -o -name "*amd*" | grep -E "\.(exe|dll)$" | head -5)

for file in "${AMD_FILES[@]}"; do
    if [[ -f "$file" ]]; then
        echo "Testing: $(basename "$file")"
        result=$(yara -w $YARA_RULES "$file" 2>/dev/null)
        if [[ -n "$result" ]]; then
            echo "  Match: $result"
        else
            echo "  No match"
        fi
    fi
done

echo ""

# Test 4: Performance test
echo "=== Test 4: Performance Test ==="
echo "Testing rule performance on multiple files..."

start_time=$(date +%s.%N)
file_count=0

# Test on first 50 files found
while IFS= read -r -d '' file && (( file_count < 50 )); do
    yara -w $YARA_RULES "$file" >/dev/null 2>&1
    ((file_count++))
done < <(find "$TEST_DIR" -type f \( -name "*.exe" -o -name "*.dll" \) -print0 | head -50)

end_time=$(date +%s.%N)
duration=$(echo "$end_time - $start_time" | bc)
fps=$(echo "scale=2; $file_count / $duration" | bc)

echo "Processed $file_count files in ${duration}s"
echo "Performance: ${fps} files/second"

echo ""
echo "=== Test Summary ==="
echo "✅ Rule validation complete"
echo "🔍 Check output above for any unexpected matches (false positives)"
echo "⚡ Performance: ${fps} files/second"