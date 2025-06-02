#!/bin/bash

# Extended Ubuntu system scanner - More paths and file types
# Scans additional system directories for comprehensive analysis

API_URL="http://localhost:3001/mcp"
CONCURRENT_JOBS=12
RESULTS_DIR="ubuntu_extended_scan"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Create results directory structure
mkdir -p "$RESULTS_DIR"/{logs,opt,snap,firmware,boot,proc,python,scripts,databases}

# Color codes
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

# Function to scan file with category
scan_file_extended() {
    local file="$1"
    local category="$2"
    local filename=$(basename "$file")
    local output_file="$RESULTS_DIR/${category}/${filename//\//_}_${TIMESTAMP}.json"
    
    # Skip if not a regular file or too large (>50MB)
    if [ ! -f "$file" ] || [ $(stat -c%s "$file" 2>/dev/null || echo 999999999) -gt 52428800 ]; then
        return
    fi
    
    # Determine analysis options based on file type
    local analysis_opts=""
    case "$category" in
        "logs")
            analysis_opts='"metadata": true, "hashes": true, "strings": true'
            ;;
        "opt"|"snap")
            analysis_opts='"metadata": true, "hashes": true, "binary_info": true, "strings": true, "threats": true'
            ;;
        "firmware"|"boot")
            analysis_opts='"metadata": true, "hashes": true, "binary_info": true, "entropy": true, "hex_dump": true, "hex_dump_size": 256'
            ;;
        "python"|"scripts")
            analysis_opts='"metadata": true, "hashes": true, "strings": true, "code_quality": true'
            ;;
        "databases")
            analysis_opts='"metadata": true, "hashes": true, "hex_dump": true, "hex_dump_size": 512'
            ;;
        "proc")
            analysis_opts='"metadata": true, "strings": true'
            ;;
        *)
            analysis_opts='"metadata": true, "hashes": true'
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
        echo -e "${GREEN}✓${NC} $category: $(basename "$file")"
    else
        echo -e "${RED}✗${NC} $category: $(basename "$file")"
        rm -f "$output_file"
    fi
}

export -f scan_file_extended
export API_URL RESULTS_DIR TIMESTAMP GREEN RED YELLOW BLUE CYAN MAGENTA NC

echo -e "${BLUE}Extended Ubuntu System Scanner${NC}"
echo "============================================"
echo "Results directory: $RESULTS_DIR"
echo "Concurrent jobs: $CONCURRENT_JOBS"
echo "============================================"

START_TIME=$(date +%s)

# 1. Scan log files
echo -e "\n${YELLOW}[1/9] Scanning System Logs${NC}"
echo "----------------------------------------"
{
    find /var/log -name "*.log" -type f -size -10M 2>/dev/null | head -20 | while read f; do echo "$f logs"; done
    find /var/log -name "syslog*" -type f -size -10M 2>/dev/null | head -5 | while read f; do echo "$f logs"; done
} | xargs -P $CONCURRENT_JOBS -I {} bash -c 'scan_file_extended $1 $2' _ $(echo {} | cut -d' ' -f1) $(echo {} | cut -d' ' -f2)

# 2. Scan /opt applications
echo -e "\n${YELLOW}[2/9] Scanning Third-Party Applications (/opt)${NC}"
echo "----------------------------------------"
{
    find /opt -type f -executable 2>/dev/null | head -30 | while read f; do echo "$f opt"; done
} | xargs -P $CONCURRENT_JOBS -I {} bash -c 'scan_file_extended $1 $2' _ $(echo {} | cut -d' ' -f1) $(echo {} | cut -d' ' -f2)

# 3. Scan snap packages
echo -e "\n${YELLOW}[3/9] Scanning Snap Packages${NC}"
echo "----------------------------------------"
{
    find /snap -name "*.snap" -type f 2>/dev/null | head -10 | while read f; do echo "$f snap"; done
    find /snap/bin -type f 2>/dev/null | head -20 | while read f; do echo "$f snap"; done
} | xargs -P $CONCURRENT_JOBS -I {} bash -c 'scan_file_extended $1 $2' _ $(echo {} | cut -d' ' -f1) $(echo {} | cut -d' ' -f2)

# 4. Scan firmware files
echo -e "\n${YELLOW}[4/9] Scanning Firmware Files${NC}"
echo "----------------------------------------"
{
    find /lib/firmware -type f -size -5M 2>/dev/null | head -25 | while read f; do echo "$f firmware"; done
    find /usr/lib/firmware -type f -size -5M 2>/dev/null | head -15 | while read f; do echo "$f firmware"; done
} | xargs -P $CONCURRENT_JOBS -I {} bash -c 'scan_file_extended $1 $2' _ $(echo {} | cut -d' ' -f1) $(echo {} | cut -d' ' -f2)

# 5. Scan boot files
echo -e "\n${YELLOW}[5/9] Scanning Boot Files${NC}"
echo "----------------------------------------"
{
    find /boot -name "vmlinuz*" -type f 2>/dev/null | head -5 | while read f; do echo "$f boot"; done
    find /boot -name "initrd*" -type f 2>/dev/null | head -5 | while read f; do echo "$f boot"; done
    find /boot/efi -type f 2>/dev/null | head -10 | while read f; do echo "$f boot"; done
} | xargs -P $CONCURRENT_JOBS -I {} bash -c 'scan_file_extended $1 $2' _ $(echo {} | cut -d' ' -f1) $(echo {} | cut -d' ' -f2)

# 6. Scan Python files
echo -e "\n${YELLOW}[6/9] Scanning Python System Files${NC}"
echo "----------------------------------------"
{
    find /usr/lib/python3/dist-packages -name "*.py" -type f 2>/dev/null | head -30 | while read f; do echo "$f python"; done
    find /usr/bin -name "*.py" -type f 2>/dev/null | head -10 | while read f; do echo "$f python"; done
} | xargs -P $CONCURRENT_JOBS -I {} bash -c 'scan_file_extended $1 $2' _ $(echo {} | cut -d' ' -f1) $(echo {} | cut -d' ' -f2)

# 7. Scan shell scripts
echo -e "\n${YELLOW}[7/9] Scanning System Shell Scripts${NC}"
echo "----------------------------------------"
{
    find /usr/bin -name "*.sh" -type f 2>/dev/null | head -20 | while read f; do echo "$f scripts"; done
    find /etc/init.d -type f 2>/dev/null | head -15 | while read f; do echo "$f scripts"; done
} | xargs -P $CONCURRENT_JOBS -I {} bash -c 'scan_file_extended $1 $2' _ $(echo {} | cut -d' ' -f1) $(echo {} | cut -d' ' -f2)

# 8. Scan database files
echo -e "\n${YELLOW}[8/9] Scanning System Database Files${NC}"
echo "----------------------------------------"
{
    find /var/lib -name "*.db" -type f -size -20M 2>/dev/null | head -15 | while read f; do echo "$f databases"; done
    find /var/lib -name "*.sqlite*" -type f -size -20M 2>/dev/null | head -10 | while read f; do echo "$f databases"; done
} | xargs -P $CONCURRENT_JOBS -I {} bash -c 'scan_file_extended $1 $2' _ $(echo {} | cut -d' ' -f1) $(echo {} | cut -d' ' -f2)

# 9. Scan /proc for interesting files
echo -e "\n${YELLOW}[9/9] Scanning Process Information${NC}"
echo "----------------------------------------"
{
    echo "/proc/cpuinfo proc"
    echo "/proc/meminfo proc"
    echo "/proc/version proc"
    echo "/proc/modules proc"
    echo "/proc/cmdline proc"
} | xargs -P $CONCURRENT_JOBS -I {} bash -c 'scan_file_extended $1 $2' _ $(echo {} | cut -d' ' -f1) $(echo {} | cut -d' ' -f2)

END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

# Generate comprehensive report
echo -e "\n${BLUE}Generating Analysis Report${NC}"
echo "============================================"

# Count results
LOGS_COUNT=$(find "$RESULTS_DIR/logs" -name "*.json" 2>/dev/null | wc -l)
OPT_COUNT=$(find "$RESULTS_DIR/opt" -name "*.json" 2>/dev/null | wc -l)
SNAP_COUNT=$(find "$RESULTS_DIR/snap" -name "*.json" 2>/dev/null | wc -l)
FIRMWARE_COUNT=$(find "$RESULTS_DIR/firmware" -name "*.json" 2>/dev/null | wc -l)
BOOT_COUNT=$(find "$RESULTS_DIR/boot" -name "*.json" 2>/dev/null | wc -l)
PYTHON_COUNT=$(find "$RESULTS_DIR/python" -name "*.json" 2>/dev/null | wc -l)
SCRIPTS_COUNT=$(find "$RESULTS_DIR/scripts" -name "*.json" 2>/dev/null | wc -l)
DB_COUNT=$(find "$RESULTS_DIR/databases" -name "*.json" 2>/dev/null | wc -l)
PROC_COUNT=$(find "$RESULTS_DIR/proc" -name "*.json" 2>/dev/null | wc -l)
TOTAL_COUNT=$((LOGS_COUNT + OPT_COUNT + SNAP_COUNT + FIRMWARE_COUNT + BOOT_COUNT + PYTHON_COUNT + SCRIPTS_COUNT + DB_COUNT + PROC_COUNT))

# Cache and string statistics
echo -e "\n${CYAN}System Analysis Statistics:${NC}"
CACHE_STATS=$(curl -s http://localhost:3001/cache/stats)
echo "$CACHE_STATS" | jq -r '
    "Total analyses: \(.statistics.total_analyses)",
    "Unique files: \(.statistics.unique_files)", 
    "Avg execution time: \(.statistics.avg_execution_time_ms)ms",
    "Cache size: \(.metadata.cache_size_bytes | tonumber / 1048576 | floor)MB"
'

# High entropy files (possible encryption/compression)
echo -e "\n${MAGENTA}High Entropy Files Detected:${NC}"
find "$RESULTS_DIR" -name "*.json" -exec jq -r '.result.content[0].text | fromjson | select(.entropy.overall_entropy > 7.0) | "\(.entropy.overall_entropy | tostring[0:4]) \(.file_path)"' {} \; 2>/dev/null | sort -rn | head -10

# Threat detection summary
echo -e "\n${RED}Potential Threats Detected:${NC}"
find "$RESULTS_DIR" -name "*.json" -exec jq -r '.result.content[0].text | fromjson | select(.threats) | .file_path' {} \; 2>/dev/null | head -10

# Generate detailed report
REPORT_FILE="$RESULTS_DIR/extended_ubuntu_report_${TIMESTAMP}.txt"
{
    echo "Extended Ubuntu System Analysis Report"
    echo "====================================="
    echo "Generated: $(date)"
    echo "Duration: $DURATION seconds"
    echo "Total files analyzed: $TOTAL_COUNT"
    echo ""
    echo "Files by Category:"
    echo "- System Logs: $LOGS_COUNT"
    echo "- Third-party Apps (/opt): $OPT_COUNT"
    echo "- Snap Packages: $SNAP_COUNT"
    echo "- Firmware Files: $FIRMWARE_COUNT"
    echo "- Boot Files: $BOOT_COUNT"
    echo "- Python Files: $PYTHON_COUNT"
    echo "- Shell Scripts: $SCRIPTS_COUNT"
    echo "- Database Files: $DB_COUNT"
    echo "- Process Info: $PROC_COUNT"
    echo ""
    echo "Performance Metrics:"
    echo "- Scan rate: $(echo "scale=2; $TOTAL_COUNT / $DURATION" | bc) files/sec"
    echo "- Concurrent jobs: $CONCURRENT_JOBS"
    echo ""
    echo "File Size Distribution:"
    find "$RESULTS_DIR" -name "*.json" -exec jq -r '.result.content[0].text | fromjson | .metadata.file_size' {} \; 2>/dev/null | \
        awk '{
            if ($1 < 1024) size="<1KB"
            else if ($1 < 1048576) size="1KB-1MB"
            else if ($1 < 10485760) size="1MB-10MB"
            else size=">10MB"
            count[size]++
        } END {for (s in count) print s": "count[s]" files"}'
} > "$REPORT_FILE"

echo -e "\n${GREEN}Extended Scan Complete!${NC}"
echo "============================================"
echo "Total files scanned: $TOTAL_COUNT"
echo "Duration: $DURATION seconds"
echo "Scan rate: $(echo "scale=2; $TOTAL_COUNT / $DURATION" | bc) files/sec"
echo ""
echo "Category breakdown:"
echo "- Logs: $LOGS_COUNT | Firmware: $FIRMWARE_COUNT | Python: $PYTHON_COUNT"
echo "- /opt: $OPT_COUNT | Boot: $BOOT_COUNT | Scripts: $SCRIPTS_COUNT"  
echo "- Snap: $SNAP_COUNT | Databases: $DB_COUNT | /proc: $PROC_COUNT"
echo ""
echo "Full report: $REPORT_FILE"