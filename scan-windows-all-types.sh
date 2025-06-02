#!/bin/bash

# Comprehensive Windows scanner - All file types
# Scans EXE, DLL, MSI, SCR, COM, SYS, DRV, OCX, and more

API_URL="http://localhost:3001/mcp"
RESULTS_DIR="windows_comprehensive_scan"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
CONCURRENT_JOBS=10

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

mkdir -p "$RESULTS_DIR"/{exe,dll,msi,sys,other}

echo -e "${BLUE}Comprehensive Windows File Scanner${NC}"
echo "======================================="
echo "Scanning all executable file types"
echo "======================================="

# Function to scan any file
scan_file() {
    local filepath="$1"
    local filetype="$2"
    local filename=$(basename "$filepath")
    local app_path=$(echo "$filepath" | sed 's|/windows/||' | sed 's|/[^/]*$||')
    
    # Skip very large files (>100MB)
    local filesize=$(docker exec file-scanner-http stat -c%s "$filepath" 2>/dev/null || echo 0)
    if [ $filesize -gt 104857600 ]; then
        echo -e "Skipping large file: $filename ($(($filesize/1048576))MB)"
        return
    fi
    
    echo -ne "[$filetype] $app_path/$filename... "
    
    # Determine analysis options based on file type
    local analysis_opts=""
    case "$filetype" in
        "EXE"|"SCR"|"COM")
            analysis_opts='"metadata": true, "hashes": true, "binary_info": true, "threats": true, "signatures": true, "behavioral": true, "entropy": true'
            ;;
        "DLL"|"OCX")
            analysis_opts='"metadata": true, "hashes": true, "binary_info": true, "threats": true, "symbols": true, "dependencies": true'
            ;;
        "MSI"|"MSP")
            analysis_opts='"metadata": true, "hashes": true, "strings": true, "threats": true, "entropy": true'
            ;;
        "SYS"|"DRV")
            analysis_opts='"metadata": true, "hashes": true, "binary_info": true, "threats": true, "vulnerabilities": true'
            ;;
        *)
            analysis_opts='"metadata": true, "hashes": true, "threats": true'
            ;;
    esac
    
    # Create the JSON-RPC request
    local response=$(curl -s -X POST "$API_URL" \
        -H "Content-Type: application/json" \
        -d "{
            \"jsonrpc\": \"2.0\",
            \"id\": 1,
            \"method\": \"tools/call\",
            \"params\": {
                \"name\": \"analyze_file\",
                \"arguments\": {
                    \"file_path\": \"$filepath\",
                    $analysis_opts
                }
            }
        }")
    
    # Save response
    local safe_name=$(echo "$filename" | tr ' ' '_' | tr '/' '_')
    local output_file="$RESULTS_DIR/${filetype,,}/${safe_name}_${TIMESTAMP}.json"
    echo "$response" > "$output_file"
    
    # Extract key information
    local threat_level=$(echo "$response" | jq -r '.result.content[0].text' 2>/dev/null | jq -r '.threats.threat_level // "Unknown"' 2>/dev/null)
    local is_signed=$(echo "$response" | jq -r '.result.content[0].text' 2>/dev/null | jq -r '.signatures.is_signed // false' 2>/dev/null)
    local entropy=$(echo "$response" | jq -r '.result.content[0].text' 2>/dev/null | jq -r '.entropy.overall_entropy // 0' 2>/dev/null)
    local file_size=$(echo "$response" | jq -r '.result.content[0].text' 2>/dev/null | jq -r '.metadata.file_size // 0' 2>/dev/null)
    
    # Display result with color coding
    local status=""
    if [ "$threat_level" != "Clean" ] && [ "$threat_level" != "Unknown" ]; then
        status="${RED}[THREAT: $threat_level]${NC}"
    elif [ "$is_signed" == "false" ]; then
        if [ $(echo "$entropy > 7.5" | bc -l) -eq 1 ]; then
            status="${MAGENTA}[Unsigned/High-Entropy: $entropy]${NC}"
        else
            status="${YELLOW}[Unsigned]${NC}"
        fi
    else
        status="${GREEN}[Clean/Signed]${NC}"
    fi
    
    echo -e "$status ($(($file_size/1024))KB)"
}

export -f scan_file
export API_URL RESULTS_DIR TIMESTAMP GREEN RED YELLOW BLUE MAGENTA CYAN NC

# Start scanning
START_TIME=$(date +%s)

# 1. Scan EXE files
echo -e "\n${YELLOW}[1/7] Scanning Executable Files (.exe)${NC}"
echo "----------------------------------------"
docker exec file-scanner-http find "/windows/Program Files (x86)" -name "*.exe" -type f 2>/dev/null | head -30 | \
    while read f; do scan_file "$f" "EXE"; done

# 2. Scan DLL files
echo -e "\n${YELLOW}[2/7] Scanning Dynamic Link Libraries (.dll)${NC}"
echo "----------------------------------------"
docker exec file-scanner-http find "/windows/Program Files (x86)" -name "*.dll" -type f 2>/dev/null | head -40 | \
    while read f; do scan_file "$f" "DLL"; done

# 3. Scan MSI installers
echo -e "\n${YELLOW}[3/7] Scanning Windows Installers (.msi, .msp)${NC}"
echo "----------------------------------------"
docker exec file-scanner-http find "/windows/Program Files (x86)" \( -name "*.msi" -o -name "*.msp" \) -type f 2>/dev/null | head -20 | \
    while read f; do scan_file "$f" "MSI"; done

# 4. Scan system/driver files
echo -e "\n${YELLOW}[4/7] Scanning System/Driver Files (.sys, .drv)${NC}"
echo "----------------------------------------"
docker exec file-scanner-http find "/windows" \( -name "*.sys" -o -name "*.drv" \) -type f 2>/dev/null | head -20 | \
    while read f; do scan_file "$f" "SYS"; done

# 5. Scan screensaver files
echo -e "\n${YELLOW}[5/7] Scanning Screensaver Files (.scr)${NC}"
echo "----------------------------------------"
docker exec file-scanner-http find "/windows" -name "*.scr" -type f 2>/dev/null | head -10 | \
    while read f; do scan_file "$f" "SCR"; done

# 6. Scan COM executables
echo -e "\n${YELLOW}[6/7] Scanning COM Executables (.com)${NC}"
echo "----------------------------------------"
docker exec file-scanner-http find "/windows" -name "*.com" -type f 2>/dev/null | head -10 | \
    while read f; do scan_file "$f" "COM"; done

# 7. Scan OCX controls
echo -e "\n${YELLOW}[7/7] Scanning ActiveX Controls (.ocx)${NC}"
echo "----------------------------------------"
docker exec file-scanner-http find "/windows/Program Files (x86)" -name "*.ocx" -type f 2>/dev/null | head -20 | \
    while read f; do scan_file "$f" "OCX"; done

END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

# Generate comprehensive report
echo -e "\n${BLUE}=== Security Analysis Report ===${NC}"
echo "======================================="

# Count files by type
EXE_COUNT=$(find "$RESULTS_DIR/exe" -name "*.json" 2>/dev/null | wc -l)
DLL_COUNT=$(find "$RESULTS_DIR/dll" -name "*.json" 2>/dev/null | wc -l)
MSI_COUNT=$(find "$RESULTS_DIR/msi" -name "*.json" 2>/dev/null | wc -l)
SYS_COUNT=$(find "$RESULTS_DIR/sys" -name "*.json" 2>/dev/null | wc -l)
OTHER_COUNT=$(find "$RESULTS_DIR/other" -name "*.json" 2>/dev/null | wc -l)
TOTAL_COUNT=$((EXE_COUNT + DLL_COUNT + MSI_COUNT + SYS_COUNT + OTHER_COUNT))

echo "Files Scanned:"
echo "- Executables (.exe): $EXE_COUNT"
echo "- Libraries (.dll): $DLL_COUNT"
echo "- Installers (.msi/.msp): $MSI_COUNT"
echo "- Drivers (.sys/.drv): $SYS_COUNT"
echo "- Other types: $OTHER_COUNT"
echo "- Total: $TOTAL_COUNT files in $DURATION seconds"

# Threat analysis
echo -e "\n${RED}=== Threat Analysis ===${NC}"
THREATS=$(find "$RESULTS_DIR" -name "*.json" -exec jq -r '.result.content[0].text' {} \; 2>/dev/null | \
    jq -r 'select(.threats.threat_level != "Clean" and .threats.threat_level != null) | .file_path' 2>/dev/null | wc -l)
echo "Total threats detected: $THREATS"

if [ $THREATS -gt 0 ]; then
    echo -e "\n${RED}Detected Threats by Type:${NC}"
    find "$RESULTS_DIR" -name "*.json" -exec jq -r '.result.content[0].text' {} \; 2>/dev/null | \
        jq -r 'select(.threats.threat_level != "Clean" and .threats.threat_level != null) | 
        "\(.file_path | split("/") | .[-1]) [\(.file_path | split(".") | .[-1] | ascii_upcase)] - \(.threats.threat_level) - \(.threats.matches[0].rule_identifier // "Unknown")"' 2>/dev/null | \
        sort | head -20
fi

# Unsigned files by type
echo -e "\n${YELLOW}=== Unsigned Files Summary ===${NC}"
echo "Top unsigned EXEs:"
find "$RESULTS_DIR/exe" -name "*.json" -exec jq -r '.result.content[0].text' {} \; 2>/dev/null | \
    jq -r 'select(.signatures.is_signed == false) | .file_path | split("/") | .[-1]' 2>/dev/null | head -5

echo -e "\nTop unsigned DLLs:"
find "$RESULTS_DIR/dll" -name "*.json" -exec jq -r '.result.content[0].text' {} \; 2>/dev/null | \
    jq -r 'select(.signatures.is_signed == false) | .file_path | split("/") | .[-1]' 2>/dev/null | head -5

# High entropy analysis
echo -e "\n${MAGENTA}=== High Entropy Files (Possibly Packed) ===${NC}"
find "$RESULTS_DIR" -name "*.json" -exec jq -r '.result.content[0].text' {} \; 2>/dev/null | \
    jq -r 'select(.entropy.overall_entropy > 7.5) | 
    "\(.file_path | split("/") | .[-1]) [\(.file_path | split(".") | .[-1] | ascii_upcase)] - Entropy: \(.entropy.overall_entropy | tostring[0:5])"' 2>/dev/null | \
    sort -k4 -rn | head -10

# File size distribution
echo -e "\n${CYAN}=== File Size Distribution ===${NC}"
find "$RESULTS_DIR" -name "*.json" -exec jq -r '.result.content[0].text' {} \; 2>/dev/null | \
    jq -r '.metadata.file_size' 2>/dev/null | \
    awk '{
        if ($1 < 102400) size="<100KB"
        else if ($1 < 1048576) size="100KB-1MB"
        else if ($1 < 10485760) size="1MB-10MB"
        else if ($1 < 52428800) size="10MB-50MB"
        else size=">50MB"
        count[size]++
        total++
    } END {
        for (s in count) printf "%-15s: %d files (%.1f%%)\n", s, count[s], (count[s]/total)*100
    }' | sort

# Performance stats
echo -e "\n${BLUE}=== Performance Statistics ===${NC}"
CACHE_STATS=$(curl -s http://localhost:3001/cache/stats)
echo "$CACHE_STATS" | jq -r '
    "Total analyses performed: \(.statistics.total_analyses)",
    "Average analysis time: \(.statistics.avg_execution_time_ms)ms",
    "Cache size: \(.metadata.cache_size_bytes | tonumber / 1048576 | floor)MB",
    "Scan rate: '"$((TOTAL_COUNT / DURATION))"' files/second"
'

# Generate detailed report file
REPORT_FILE="$RESULTS_DIR/comprehensive_report_${TIMESTAMP}.txt"
{
    echo "Windows Comprehensive Security Scan Report"
    echo "=========================================="
    echo "Generated: $(date)"
    echo "Duration: $DURATION seconds"
    echo ""
    echo "Files Scanned by Type:"
    echo "- EXE: $EXE_COUNT"
    echo "- DLL: $DLL_COUNT"
    echo "- MSI: $MSI_COUNT"
    echo "- SYS: $SYS_COUNT"
    echo "- Other: $OTHER_COUNT"
    echo "- Total: $TOTAL_COUNT"
    echo ""
    echo "Security Findings:"
    echo "- Threats detected: $THREATS"
    echo "- Unsigned files: $(find "$RESULTS_DIR" -name "*.json" -exec jq -r '.result.content[0].text' {} \; 2>/dev/null | jq -r 'select(.signatures.is_signed == false) | .file_path' 2>/dev/null | wc -l)"
    echo "- High entropy files: $(find "$RESULTS_DIR" -name "*.json" -exec jq -r '.result.content[0].text' {} \; 2>/dev/null | jq -r 'select(.entropy.overall_entropy > 7.5) | .file_path' 2>/dev/null | wc -l)"
} > "$REPORT_FILE"

echo -e "\n${GREEN}Scan complete! Full report: $REPORT_FILE${NC}"