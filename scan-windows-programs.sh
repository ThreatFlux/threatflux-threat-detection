#!/bin/bash

# Windows Program Files (x86) Scanner
# Analyzes Windows applications, DLLs, and executables for security threats

API_URL="http://localhost:3001/mcp"
CONCURRENT_JOBS=10
RESULTS_DIR="windows_programs_scan"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
WINDOWS_PATH="/media/vtriple/A8E8E234E8E20084/Program Files (x86)"

# Create results directory structure
mkdir -p "$RESULTS_DIR"/{executables,dlls,installers,configs,suspicious,analysis}

# Color codes
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

# Function to scan Windows files with enhanced analysis
scan_windows_file() {
    local file="$1"
    local category="$2"
    local filename=$(basename "$file")
    local safe_filename="${filename//[^a-zA-Z0-9._-]/_}"
    local output_file="$RESULTS_DIR/${category}/${safe_filename}_${TIMESTAMP}.json"
    
    # Skip if not a regular file or too large (>50MB)
    if [ ! -f "$file" ] || [ $(stat -c%s "$file" 2>/dev/null || echo 999999999) -gt 52428800 ]; then
        return
    fi
    
    # Enhanced analysis for Windows files
    local analysis_opts=""
    case "$category" in
        "executables")
            analysis_opts='"metadata": true, "hashes": true, "binary_info": true, "strings": true, "threats": true, "signatures": true, "behavioral": true, "vulnerabilities": true'
            ;;
        "dlls")
            analysis_opts='"metadata": true, "hashes": true, "binary_info": true, "symbols": true, "threats": true, "dependencies": true'
            ;;
        "installers")
            analysis_opts='"metadata": true, "hashes": true, "strings": true, "threats": true, "entropy": true'
            ;;
        "configs")
            analysis_opts='"metadata": true, "hashes": true, "strings": true'
            ;;
        "suspicious")
            analysis_opts='"metadata": true, "hashes": true, "binary_info": true, "strings": true, "threats": true, "behavioral": true, "entropy": true, "disassembly": true, "yara_indicators": true'
            ;;
    esac
    
    # Create request
    local request=$(cat <<EOF
{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {
        "name": "analyze_file",
        "arguments": {
            "file_path": "$file",
            $analysis_opts
        }
    }
}
EOF
)
    
    # Send request
    curl -s -X POST "$API_URL" \
        -H "Content-Type: application/json" \
        -d "$request" \
        -o "$output_file" 2>/dev/null
    
    if [ $? -eq 0 ] && [ -s "$output_file" ]; then
        echo -e "${GREEN}✓${NC} $category: $filename"
        
        # Check for threats
        local threats=$(jq -r '.result.content[0].text | fromjson | .threats // empty' "$output_file" 2>/dev/null)
        if [ ! -z "$threats" ]; then
            echo -e "  ${RED}⚠ THREAT DETECTED${NC} in $filename"
        fi
    else
        echo -e "${RED}✗${NC} $category: $filename"
        rm -f "$output_file"
    fi
}

export -f scan_windows_file
export API_URL RESULTS_DIR TIMESTAMP GREEN RED YELLOW BLUE CYAN MAGENTA NC

echo -e "${BLUE}Windows Program Files (x86) Scanner${NC}"
echo "================================================"
echo "Target directory: $WINDOWS_PATH"
echo "Results directory: $RESULTS_DIR"
echo "Concurrent jobs: $CONCURRENT_JOBS"
echo "================================================"

# Check if Windows path exists
if [ ! -d "$WINDOWS_PATH" ]; then
    echo -e "${RED}Error: Windows path not found!${NC}"
    echo "Path: $WINDOWS_PATH"
    exit 1
fi

START_TIME=$(date +%s)

# 1. Scan executable files
echo -e "\n${YELLOW}[1/5] Scanning Windows Executables (.exe)${NC}"
echo "------------------------------------------------"
{
    find "$WINDOWS_PATH" -name "*.exe" -type f 2>/dev/null | head -50 | while read f; do echo "$f executables"; done
} | while IFS=' ' read -r filepath category; do
    scan_windows_file "$filepath" "$category"
done

# 2. Scan DLL files
echo -e "\n${YELLOW}[2/5] Scanning Windows Libraries (.dll)${NC}"
echo "------------------------------------------------"
{
    find "$WINDOWS_PATH" -name "*.dll" -type f 2>/dev/null | head -40 | while read f; do echo "$f dlls"; done
} | while IFS=' ' read -r filepath category; do
    scan_windows_file "$filepath" "$category"
done

# 3. Scan installer files
echo -e "\n${YELLOW}[3/5] Scanning Installer Files (.msi, .msp)${NC}"
echo "------------------------------------------------"
{
    find "$WINDOWS_PATH" \( -name "*.msi" -o -name "*.msp" \) -type f 2>/dev/null | head -20 | while read f; do echo "$f installers"; done
} | while IFS=' ' read -r filepath category; do
    scan_windows_file "$filepath" "$category"
done

# 4. Scan configuration files
echo -e "\n${YELLOW}[4/5] Scanning Configuration Files${NC}"
echo "------------------------------------------------"
{
    find "$WINDOWS_PATH" \( -name "*.ini" -o -name "*.config" -o -name "*.xml" \) -type f -size -1M 2>/dev/null | head -30 | while read f; do echo "$f configs"; done
} | while IFS=' ' read -r filepath category; do
    scan_windows_file "$filepath" "$category"
done

# 5. Look for suspicious files
echo -e "\n${YELLOW}[5/5] Scanning for Suspicious Files${NC}"
echo "------------------------------------------------"
{
    # Files with suspicious extensions or patterns
    find "$WINDOWS_PATH" \( -name "*.scr" -o -name "*.bat" -o -name "*.cmd" -o -name "*.vbs" -o -name "*.ps1" \) -type f 2>/dev/null | head -20 | while read f; do echo "$f suspicious"; done
    # Hidden executables
    find "$WINDOWS_PATH" -name ".*exe" -type f 2>/dev/null | head -10 | while read f; do echo "$f suspicious"; done
} | while IFS=' ' read -r filepath category; do
    scan_windows_file "$filepath" "$category"
done

END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

# Generate analysis report
echo -e "\n${BLUE}Generating Security Analysis Report${NC}"
echo "================================================"

# Count results
EXE_COUNT=$(find "$RESULTS_DIR/executables" -name "*.json" 2>/dev/null | wc -l)
DLL_COUNT=$(find "$RESULTS_DIR/dlls" -name "*.json" 2>/dev/null | wc -l)
INSTALLER_COUNT=$(find "$RESULTS_DIR/installers" -name "*.json" 2>/dev/null | wc -l)
CONFIG_COUNT=$(find "$RESULTS_DIR/configs" -name "*.json" 2>/dev/null | wc -l)
SUSPICIOUS_COUNT=$(find "$RESULTS_DIR/suspicious" -name "*.json" 2>/dev/null | wc -l)
TOTAL_COUNT=$((EXE_COUNT + DLL_COUNT + INSTALLER_COUNT + CONFIG_COUNT + SUSPICIOUS_COUNT))

# Threat analysis
echo -e "\n${RED}Threat Analysis Summary:${NC}"
THREATS_FOUND=$(find "$RESULTS_DIR" -name "*.json" -exec jq -r '.result.content[0].text | fromjson | select(.threats) | .file_path' {} \; 2>/dev/null | wc -l)
echo "Total threats detected: $THREATS_FOUND"

if [ $THREATS_FOUND -gt 0 ]; then
    echo -e "\n${RED}Files with detected threats:${NC}"
    find "$RESULTS_DIR" -name "*.json" -exec jq -r '.result.content[0].text | fromjson | select(.threats) | .file_path' {} \; 2>/dev/null | head -10
fi

# High entropy files (packed/encrypted)
echo -e "\n${MAGENTA}Potentially Packed/Encrypted Files:${NC}"
find "$RESULTS_DIR" -name "*.json" -exec jq -r '.result.content[0].text | fromjson | select(.entropy.overall_entropy > 7.5) | "\(.entropy.overall_entropy | tostring[0:4]) \(.file_path)"' {} \; 2>/dev/null | sort -rn | head -10

# Unsigned executables
echo -e "\n${YELLOW}Unsigned Executables:${NC}"
find "$RESULTS_DIR/executables" -name "*.json" -exec jq -r '.result.content[0].text | fromjson | select(.signatures == null or .signatures.is_signed == false) | .file_path' {} \; 2>/dev/null | head -10

# Generate detailed report
REPORT_FILE="$RESULTS_DIR/windows_security_report_${TIMESTAMP}.txt"
{
    echo "Windows Program Files Security Analysis Report"
    echo "============================================="
    echo "Generated: $(date)"
    echo "Target: $WINDOWS_PATH"
    echo "Duration: $DURATION seconds"
    echo ""
    echo "Files Analyzed:"
    echo "- Executables (.exe): $EXE_COUNT"
    echo "- Libraries (.dll): $DLL_COUNT"
    echo "- Installers (.msi/.msp): $INSTALLER_COUNT"
    echo "- Config files: $CONFIG_COUNT"
    echo "- Suspicious files: $SUSPICIOUS_COUNT"
    echo "- Total: $TOTAL_COUNT"
    echo ""
    echo "Security Findings:"
    echo "- Threats detected: $THREATS_FOUND"
    echo "- High entropy files: $(find "$RESULTS_DIR" -name "*.json" -exec jq -r '.result.content[0].text | fromjson | select(.entropy.overall_entropy > 7.5) | .file_path' {} \; 2>/dev/null | wc -l)"
    echo "- Unsigned executables: $(find "$RESULTS_DIR/executables" -name "*.json" -exec jq -r '.result.content[0].text | fromjson | select(.signatures == null or .signatures.is_signed == false) | .file_path' {} \; 2>/dev/null | wc -l)"
    echo ""
    echo "Top Applications Scanned:"
    find "$RESULTS_DIR" -name "*.json" -exec jq -r '.result.content[0].text | fromjson | .file_path' {} \; 2>/dev/null | grep -oP '(?<=Program Files \(x86\)/)[^/]+' | sort | uniq -c | sort -rn | head -20
} > "$REPORT_FILE"

# Cache statistics
echo -e "\n${CYAN}Performance Statistics:${NC}"
curl -s http://localhost:3001/cache/stats | jq -r '
    "Total analyses: \(.statistics.total_analyses)",
    "Avg execution time: \(.statistics.avg_execution_time_ms)ms",
    "Cache size: \(.metadata.cache_size_bytes | tonumber / 1048576 | floor)MB"
'

echo -e "\n${GREEN}Windows Program Files Scan Complete!${NC}"
echo "================================================"
echo "Total files scanned: $TOTAL_COUNT"
echo "Duration: $DURATION seconds"
echo "Threats detected: $THREATS_FOUND"
echo ""
echo "Category breakdown:"
echo "- Executables: $EXE_COUNT"
echo "- DLLs: $DLL_COUNT"
echo "- Installers: $INSTALLER_COUNT"
echo "- Config files: $CONFIG_COUNT"
echo "- Suspicious: $SUSPICIOUS_COUNT"
echo ""
echo "Full report: $REPORT_FILE"