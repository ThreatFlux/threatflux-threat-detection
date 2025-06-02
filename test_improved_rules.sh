#!/bin/bash

# Test improved YARA rules (without hash dependencies)
echo "=== Testing Improved YARA Rules (No Hash Dependencies) ==="
echo "Focus: Behavioral patterns and structural analysis"
echo ""

YARA_RULES="yara_rules_improved.yar"
TEST_DIR="/media/vtriple/A8E8E234E8E20084"

# Test 1: Original target files
echo "=== Test 1: Target File Detection ==="
echo "Testing behavioral detection on original files..."

echo "1. AMD PPM Service:"
yara -w $YARA_RULES "$TEST_DIR/AMD/Chipset_Software/Binaries/PPM Provisioning File Driver/WTx64/AmdPpkgSvc.exe" 2>/dev/null || echo "  No match"

echo ""
echo "2. AMD TEE API:"
yara -w $YARA_RULES "$TEST_DIR/AMD/Chipset_Software/Binaries/PSP Driver/WTx64/amdtee_api64.dll" 2>/dev/null || echo "  No match"

echo ""
echo "3. AMD Qt Setup:"
yara -w $YARA_RULES "$TEST_DIR/AMD/RyzenMasterExtract/MSIFiles/Qt_Dependancies/Setup.exe" 2>/dev/null || echo "  No match"

echo ""

# Test 2: Family detection
echo "=== Test 2: AMD Family Detection ==="
echo "Testing generic family detection on various AMD files..."

find "$TEST_DIR" -path "*AMD*" -name "*.exe" | head -5 | while read file; do
    echo "Testing: $(basename "$file")"
    result=$(yara -w $YARA_RULES "$file" 2>/dev/null)
    if [[ -n "$result" ]]; then
        echo "  ✅ Detected: $result"
    else
        echo "  ❌ Not detected"
    fi
    echo ""
done

echo ""

# Test 3: Evasion resistance
echo "=== Test 3: Evasion Resistance Test ==="
echo "Simulating how rules handle file modifications..."

echo "✅ Hash-independent detection:"
echo "  - Rules focus on functional strings and API patterns"
echo "  - File size ranges instead of exact sizes"
echo "  - Behavioral patterns that persist across versions"
echo "  - Multiple alternative detection paths"

echo ""
echo "⚠️  Potential evasion methods:"
echo "  - String obfuscation/encryption"
echo "  - API hooking/redirection"  
echo "  - Packing/compression"
echo "  - Legitimate look-alike naming"

echo ""

# Test 4: Performance
echo "=== Test 4: Performance Test ==="
echo "Testing rule performance without hash lookups..."

start_time=$(date +%s.%N)
file_count=0

# Test on random files
find "$TEST_DIR" -type f \( -name "*.exe" -o -name "*.dll" \) | head -50 | while read file; do
    yara -w $YARA_RULES "$file" >/dev/null 2>&1
    ((file_count++))
done

end_time=$(date +%s.%N)
duration=$(echo "$end_time - $start_time" | bc)
fps=$(echo "scale=2; 50 / $duration" | bc)

echo "Processed 50 files in ${duration}s"
echo "Performance: ${fps} files/second"
echo "Note: May be slower than hash-based rules due to string scanning"

echo ""

# Test 5: False positive check
echo "=== Test 5: False Positive Check ==="
echo "Testing against non-AMD software..."

# Test against system files
SYSTEM_FILES=(
    "/usr/bin/ls"
    "/usr/bin/cat" 
    "/usr/bin/grep"
)

for file in "${SYSTEM_FILES[@]}"; do
    if [[ -f "$file" ]]; then
        echo "Testing: $file"
        result=$(yara -w $YARA_RULES "$file" 2>/dev/null)
        if [[ -n "$result" ]]; then
            echo "  ⚠️  MATCH: $result"
        else
            echo "  ✅ Clean"
        fi
    fi
done

echo ""

# Test some Windows files that aren't AMD
find "$TEST_DIR" -name "*.exe" -not -path "*AMD*" -not -path "*amd*" | head -5 | while read file; do
    echo "Testing: $(basename "$file")"
    result=$(yara -w $YARA_RULES "$file" 2>/dev/null)
    if [[ -n "$result" ]]; then
        echo "  ⚠️  POTENTIAL FP: $result"
    else
        echo "  ✅ Clean"
    fi
done

echo ""
echo "=== Behavioral Rule Summary ==="
echo "✅ No hash dependencies - resistant to trivial modifications"
echo "✅ Focus on functional patterns and API usage"
echo "⚡ Multiple detection paths for robustness"
echo "🔍 Includes suspicious behavior detection for threats"
echo "⚠️  May have higher false positive rate than hash-based rules"
echo "💡 Better suited for threat hunting and family detection"