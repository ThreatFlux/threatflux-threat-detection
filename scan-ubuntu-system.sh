#!/bin/bash

# Comprehensive Ubuntu system scanner
# Analyzes various system paths and file types

API_URL="http://localhost:3001/mcp"
CONCURRENT_JOBS=8
RESULTS_DIR="ubuntu_scan_results"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Create results directory structure
mkdir -p "$RESULTS_DIR"/{binaries,libraries,configs,services,kernel}

# Color codes for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to scan a single file with category
scan_file_categorized() {
    local file="$1"
    local category="$2"
    local filename=$(basename "$file")
    local output_file="$RESULTS_DIR/${category}/${filename}_${TIMESTAMP}.json"
    
    # Skip if not a regular file or if too large (>100MB)
    if [ ! -f "$file" ] || [ $(stat -c%s "$file" 2>/dev/null || echo 999999999) -gt 104857600 ]; then
        return
    fi
    
    # Determine analysis options based on category
    local analysis_opts=""
    case "$category" in
        "binaries")
            analysis_opts='"metadata": true, "hashes": true, "binary_info": true, "strings": true, "entropy": true'
            ;;
        "libraries")
            analysis_opts='"metadata": true, "hashes": true, "binary_info": true, "symbols": true'
            ;;
        "configs")
            analysis_opts='"metadata": true, "hashes": true, "strings": true'
            ;;
        "services")
            analysis_opts='"metadata": true, "hashes": true, "strings": true, "behavioral": true'
            ;;
        "kernel")
            analysis_opts='"metadata": true, "hashes": true, "binary_info": true, "symbols": true, "vulnerabilities": true'
            ;;
    esac
    
    # Create JSON-RPC request
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
        echo -e "${GREEN}✓${NC} $category: $(basename "$file")"
    else
        echo -e "${RED}✗${NC} $category: $(basename "$file")"
        rm -f "$output_file"
    fi
}

# Export functions for parallel execution
export -f scan_file_categorized
export API_URL RESULTS_DIR TIMESTAMP GREEN RED YELLOW BLUE NC

echo -e "${BLUE}Ubuntu System Scanner${NC}"
echo "========================================"
echo "Results directory: $RESULTS_DIR"
echo "Concurrent jobs: $CONCURRENT_JOBS"
echo "========================================"

# Start timer
START_TIME=$(date +%s)

# 1. Scan system binaries
echo -e "\n${YELLOW}[1/5] Scanning System Binaries${NC}"
echo "----------------------------------------"
{
    find /usr/sbin -maxdepth 1 -type f 2>/dev/null | head -20 | while read f; do echo "$f binaries"; done
    find /sbin -maxdepth 1 -type f 2>/dev/null | head -10 | while read f; do echo "$f binaries"; done
} | xargs -P $CONCURRENT_JOBS -I {} bash -c 'scan_file_categorized $1 $2' _ $(echo {} | cut -d' ' -f1) $(echo {} | cut -d' ' -f2)

# 2. Scan system libraries
echo -e "\n${YELLOW}[2/5] Scanning System Libraries${NC}"
echo "----------------------------------------"
{
    find /usr/lib/x86_64-linux-gnu -name "*.so*" -type f 2>/dev/null | head -30 | while read f; do echo "$f libraries"; done
    find /lib/x86_64-linux-gnu -name "*.so*" -type f 2>/dev/null | head -20 | while read f; do echo "$f libraries"; done
} | xargs -P $CONCURRENT_JOBS -I {} bash -c 'scan_file_categorized $1 $2' _ $(echo {} | cut -d' ' -f1) $(echo {} | cut -d' ' -f2)

# 3. Scan configuration files
echo -e "\n${YELLOW}[3/5] Scanning Configuration Files${NC}"
echo "----------------------------------------"
{
    find /etc -maxdepth 2 -name "*.conf" -type f 2>/dev/null | head -20 | while read f; do echo "$f configs"; done
    find /etc/systemd -name "*.service" -type f 2>/dev/null | head -10 | while read f; do echo "$f configs"; done
} | xargs -P $CONCURRENT_JOBS -I {} bash -c 'scan_file_categorized $1 $2' _ $(echo {} | cut -d' ' -f1) $(echo {} | cut -d' ' -f2)

# 4. Scan system services
echo -e "\n${YELLOW}[4/5] Scanning System Services${NC}"
echo "----------------------------------------"
{
    find /lib/systemd/system -name "*.service" -type f 2>/dev/null | head -15 | while read f; do echo "$f services"; done
    find /usr/lib/systemd/system -name "*.service" -type f 2>/dev/null | head -10 | while read f; do echo "$f services"; done
} | xargs -P $CONCURRENT_JOBS -I {} bash -c 'scan_file_categorized $1 $2' _ $(echo {} | cut -d' ' -f1) $(echo {} | cut -d' ' -f2)

# 5. Scan kernel modules
echo -e "\n${YELLOW}[5/5] Scanning Kernel Modules${NC}"
echo "----------------------------------------"
KERNEL_VERSION=$(uname -r)
{
    find /lib/modules/$KERNEL_VERSION -name "*.ko*" -type f 2>/dev/null | head -20 | while read f; do echo "$f kernel"; done
} | xargs -P $CONCURRENT_JOBS -I {} bash -c 'scan_file_categorized $1 $2' _ $(echo {} | cut -d' ' -f1) $(echo {} | cut -d' ' -f2)

# End timer
END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

# Generate summary report
echo -e "\n${BLUE}Generating Summary Report${NC}"
echo "========================================"

# Count results by category
BINARIES_COUNT=$(find "$RESULTS_DIR/binaries" -name "*.json" 2>/dev/null | wc -l)
LIBRARIES_COUNT=$(find "$RESULTS_DIR/libraries" -name "*.json" 2>/dev/null | wc -l)
CONFIGS_COUNT=$(find "$RESULTS_DIR/configs" -name "*.json" 2>/dev/null | wc -l)
SERVICES_COUNT=$(find "$RESULTS_DIR/services" -name "*.json" 2>/dev/null | wc -l)
KERNEL_COUNT=$(find "$RESULTS_DIR/kernel" -name "*.json" 2>/dev/null | wc -l)
TOTAL_COUNT=$((BINARIES_COUNT + LIBRARIES_COUNT + CONFIGS_COUNT + SERVICES_COUNT + KERNEL_COUNT))

# Cache statistics
echo -e "\n${YELLOW}Cache Statistics:${NC}"
CACHE_STATS=$(curl -s http://localhost:3001/cache/stats)
echo "$CACHE_STATS" | jq -r '
    "Total analyses: \(.statistics.total_analyses)",
    "Unique files: \(.statistics.unique_files)", 
    "Avg execution time: \(.statistics.avg_execution_time_ms)ms",
    "Cache size: \(.metadata.cache_size_bytes | tonumber / 1048576 | floor)MB"
'

# String statistics
echo -e "\n${YELLOW}String Analysis Summary:${NC}"
STRING_STATS=$(curl -s http://localhost:3001/strings/stats)
echo "$STRING_STATS" | jq -r '
    "Total unique strings: \(.total_unique_strings)",
    "Total occurrences: \(.total_occurrences)",
    "Files analyzed: \(.total_files_analyzed)",
    "Suspicious strings found: \(.suspicious_strings | length)"
'

# Generate detailed report
REPORT_FILE="$RESULTS_DIR/ubuntu_system_report_${TIMESTAMP}.txt"
{
    echo "Ubuntu System Scan Report"
    echo "========================="
    echo "Generated: $(date)"
    echo "Duration: $DURATION seconds"
    echo ""
    echo "Files Scanned by Category:"
    echo "- System Binaries: $BINARIES_COUNT"
    echo "- System Libraries: $LIBRARIES_COUNT"
    echo "- Configuration Files: $CONFIGS_COUNT"
    echo "- System Services: $SERVICES_COUNT"
    echo "- Kernel Modules: $KERNEL_COUNT"
    echo "- Total Files: $TOTAL_COUNT"
    echo ""
    echo "Performance:"
    echo "- Scan rate: $(echo "scale=2; $TOTAL_COUNT / $DURATION" | bc) files/sec"
    echo "- Concurrent jobs: $CONCURRENT_JOBS"
    echo ""
    echo "Top 10 Largest Files Scanned:"
    find "$RESULTS_DIR" -name "*.json" -exec jq -r '.result.content[0].text | fromjson | "\(.metadata.file_size) \(.file_path)"' {} \; 2>/dev/null | sort -rn | head -10
    echo ""
    echo "Files with High Entropy (possible encryption/packing):"
    find "$RESULTS_DIR" -name "*.json" -exec jq -r '.result.content[0].text | fromjson | select(.entropy.overall_entropy > 7.5) | "\(.entropy.overall_entropy) \(.file_path)"' {} \; 2>/dev/null | sort -rn
} > "$REPORT_FILE"

echo -e "\n${GREEN}Scan Complete!${NC}"
echo "========================================"
echo "Total files scanned: $TOTAL_COUNT"
echo "Duration: $DURATION seconds"
echo "Detailed report: $REPORT_FILE"
echo ""
echo "Results by category:"
echo "- Binaries: $BINARIES_COUNT files"
echo "- Libraries: $LIBRARIES_COUNT files"
echo "- Configs: $CONFIGS_COUNT files"
echo "- Services: $SERVICES_COUNT files"
echo "- Kernel modules: $KERNEL_COUNT files"

# Show interesting findings
echo -e "\n${YELLOW}Interesting Findings:${NC}"
echo "----------------------------------------"

# Find SUID binaries
echo -e "${BLUE}SUID Binaries found:${NC}"
find "$RESULTS_DIR/binaries" -name "*.json" -exec jq -r '.result.content[0].text | fromjson | select(.metadata.permissions | startswith("4")) | .file_path' {} \; 2>/dev/null | head -5

# Find files with suspicious strings
echo -e "\n${BLUE}Files with suspicious strings:${NC}"
curl -s -X POST http://localhost:3001/strings/filter \
    -H "Content-Type: application/json" \
    -d '{"suspicious_only": true, "min_occurrences": 2}' | \
    jq -r '.strings[:5][] | "\(.value) (found \(.count) times)"' 2>/dev/null

echo -e "\n${GREEN}Analysis complete!${NC}"