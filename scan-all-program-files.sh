#!/bin/bash

# Complete Program Files (x86) Scanner - ALL FILES
# Scans every single file regardless of type or extension

API_URL="http://localhost:3001/mcp"
RESULTS_DIR="complete_program_files_scan"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
CONCURRENT_JOBS=15
MAX_FILE_SIZE=104857600  # 100MB limit

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'

mkdir -p "$RESULTS_DIR"

echo -e "${BLUE}Complete Program Files (x86) Scanner${NC}"
echo "======================================"
echo "Scanning ALL files in Windows Program Files (x86)"
echo "Max file size: $((MAX_FILE_SIZE/1048576))MB"
echo "======================================"

# Function to scan any file
scan_any_file() {
    local filepath="$1"
    local file_number="$2"
    local total_files="$3"
    local filename=$(basename "$filepath")
    local extension="${filename##*.}"
    local app_dir=$(echo "$filepath" | sed 's|/windows/Program Files (x86)/||' | cut -d'/' -f1)
    
    # Check file size
    local filesize=$(docker exec file-scanner-http stat -c%s "$filepath" 2>/dev/null || echo 0)
    if [ $filesize -gt $MAX_FILE_SIZE ]; then
        echo -e "[$file_number/$total_files] ${YELLOW}SKIP${NC} $app_dir/$filename ($(($filesize/1048576))MB - too large)"
        return
    fi
    
    # Skip empty files
    if [ $filesize -eq 0 ]; then
        echo -e "[$file_number/$total_files] ${YELLOW}SKIP${NC} $app_dir/$filename (empty file)"
        return
    fi
    
    echo -ne "[$file_number/$total_files] Scanning $app_dir/$filename (${extension^^})... "
    
    # Determine analysis based on file extension
    local analysis_opts=""
    case "${extension,,}" in
        "exe"|"com"|"scr"|"msi"|"msp")
            analysis_opts='"metadata": true, "hashes": true, "binary_info": true, "threats": true, "signatures": true, "entropy": true'
            ;;
        "dll"|"ocx"|"sys"|"drv")
            analysis_opts='"metadata": true, "hashes": true, "binary_info": true, "threats": true, "symbols": true'
            ;;
        "txt"|"log"|"ini"|"cfg"|"conf"|"xml"|"json"|"yaml"|"yml")
            analysis_opts='"metadata": true, "hashes": true, "strings": true'
            ;;
        "js"|"vbs"|"bat"|"cmd"|"ps1"|"py"|"pl"|"rb")
            analysis_opts='"metadata": true, "hashes": true, "strings": true, "threats": true'
            ;;
        "zip"|"rar"|"7z"|"tar"|"gz"|"bz2")
            analysis_opts='"metadata": true, "hashes": true, "entropy": true'
            ;;
        "jpg"|"jpeg"|"png"|"gif"|"bmp"|"ico"|"svg")
            analysis_opts='"metadata": true, "hashes": true, "hex_dump": true, "hex_dump_size": 256'
            ;;
        "pdf"|"doc"|"docx"|"xls"|"xlsx"|"ppt"|"pptx")
            analysis_opts='"metadata": true, "hashes": true, "strings": true, "threats": true'
            ;;
        *)
            # Unknown file type - basic analysis
            analysis_opts='"metadata": true, "hashes": true, "hex_dump": true, "hex_dump_size": 512'
            ;;
    esac
    
    # Create request
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
    local safe_name=$(echo "${app_dir}_${filename}" | tr ' /' '__' | tr -cd '[:alnum:]._-')
    local output_file="$RESULTS_DIR/${safe_name}_${TIMESTAMP}.json"
    echo "$response" > "$output_file"
    
    # Extract key information
    local threat_level=$(echo "$response" | jq -r '.result.content[0].text' 2>/dev/null | jq -r '.threats.threat_level // "Clean"' 2>/dev/null)
    local is_signed=$(echo "$response" | jq -r '.result.content[0].text' 2>/dev/null | jq -r '.signatures.is_signed // false' 2>/dev/null)
    local entropy=$(echo "$response" | jq -r '.result.content[0].text' 2>/dev/null | jq -r '.entropy.overall_entropy // 0' 2>/dev/null)
    local mime_type=$(echo "$response" | jq -r '.result.content[0].text' 2>/dev/null | jq -r '.metadata.mime_type // "unknown"' 2>/dev/null)
    
    # Display result
    local status=""
    local size_kb=$((filesize/1024))
    
    if [ "$threat_level" != "Clean" ] && [ "$threat_level" != "null" ]; then
        status="${RED}[THREAT: $threat_level]${NC}"
    elif [ "$is_signed" == "false" ] && [[ "$extension" =~ ^(exe|dll|sys|ocx)$ ]]; then
        if [ $(echo "$entropy > 7.5" | bc -l 2>/dev/null || echo 0) -eq 1 ]; then
            status="${MAGENTA}[Unsigned/Packed]${NC}"
        else
            status="${YELLOW}[Unsigned]${NC}"
        fi
    elif [ "$mime_type" != "unknown" ]; then
        status="${GREEN}[${mime_type}]${NC}"
    else
        status="${CYAN}[${extension^^}]${NC}"
    fi
    
    echo -e "$status (${size_kb}KB)"
}

export -f scan_any_file
export API_URL RESULTS_DIR TIMESTAMP MAX_FILE_SIZE GREEN RED YELLOW BLUE MAGENTA CYAN WHITE NC

# Get total file count
echo -e "\n${YELLOW}Counting all files...${NC}"
TOTAL_FILES=$(docker exec file-scanner-http find "/windows/Program Files (x86)" -type f 2>/dev/null | wc -l)
echo "Total files found: $TOTAL_FILES"

if [ $TOTAL_FILES -eq 0 ]; then
    echo -e "${RED}No files found in Program Files (x86)!${NC}"
    exit 1
fi

# Process ALL files - no limit
echo -e "${GREEN}Processing ALL $TOTAL_FILES files${NC}"

echo -e "\n${BLUE}Starting comprehensive scan...${NC}"
START_TIME=$(date +%s)

# Scan all files with progress tracking
file_count=0
docker exec file-scanner-http find "/windows/Program Files (x86)" -type f 2>/dev/null | while read filepath; do
    file_count=$((file_count + 1))
    scan_any_file "$filepath" "$file_count" "$TOTAL_FILES"
    
    # Progress indicator every 1000 files for large scan
    if [ $((file_count % 1000)) -eq 0 ]; then
        echo -e "${WHITE}Progress: $file_count/$TOTAL_FILES files scanned ($(((file_count * 100) / TOTAL_FILES))%)${NC}"
    fi
done

END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

# Generate comprehensive report
echo -e "\n${BLUE}=== COMPREHENSIVE SCAN REPORT ===${NC}"
echo "================================================"

SCANNED_COUNT=$(find "$RESULTS_DIR" -name "*_${TIMESTAMP}.json" | wc -l)
echo "Files scanned: $SCANNED_COUNT"
echo "Duration: $DURATION seconds"
echo "Scan rate: $((SCANNED_COUNT / DURATION)) files/second"

# File type distribution
echo -e "\n${CYAN}File Type Distribution:${NC}"
find "$RESULTS_DIR" -name "*_${TIMESTAMP}.json" -exec jq -r '.result.content[0].text' {} \; 2>/dev/null | \
    jq -r '.metadata.mime_type // "unknown"' 2>/dev/null | \
    sort | uniq -c | sort -rn | head -15 | \
    awk '{printf "%-25s: %d files\n", $2, $1}'

# Threat summary
echo -e "\n${RED}Security Threats:${NC}"
THREATS=$(find "$RESULTS_DIR" -name "*_${TIMESTAMP}.json" -exec jq -r '.result.content[0].text' {} \; 2>/dev/null | \
    jq -r 'select(.threats.threat_level != "Clean" and .threats.threat_level != null) | .file_path' 2>/dev/null | wc -l)
echo "Total threats detected: $THREATS"

if [ $THREATS -gt 0 ]; then
    echo -e "\n${RED}Threat Details:${NC}"
    find "$RESULTS_DIR" -name "*_${TIMESTAMP}.json" -exec jq -r '.result.content[0].text' {} \; 2>/dev/null | \
        jq -r 'select(.threats.threat_level != "Clean" and .threats.threat_level != null) | 
        "\(.file_path | split("/") | .[-1]) - \(.threats.threat_level) - \(.threats.matches[0].rule_identifier // "Unknown")"' 2>/dev/null
fi

# Size analysis
echo -e "\n${CYAN}File Size Distribution:${NC}"
find "$RESULTS_DIR" -name "*_${TIMESTAMP}.json" -exec jq -r '.result.content[0].text' {} \; 2>/dev/null | \
    jq -r '.metadata.file_size' 2>/dev/null | \
    awk '{
        if ($1 < 1024) size="<1KB"
        else if ($1 < 102400) size="1KB-100KB"
        else if ($1 < 1048576) size="100KB-1MB"
        else if ($1 < 10485760) size="1MB-10MB"
        else size=">10MB"
        count[size]++
        total++
    } END {
        for (s in count) printf "%-15s: %d files (%.1f%%)\n", s, count[s], (count[s]/total)*100
    }' | sort

# Application breakdown
echo -e "\n${BLUE}Top Applications by File Count:${NC}"
find "$RESULTS_DIR" -name "*_${TIMESTAMP}.json" -exec jq -r '.result.content[0].text' {} \; 2>/dev/null | \
    jq -r '.file_path' 2>/dev/null | \
    sed 's|.*/Program Files (x86)/||' | cut -d'/' -f1 | \
    sort | uniq -c | sort -rn | head -10 | \
    awk '{printf "%-30s: %d files\n", $2, $1}'

# Cache performance
echo -e "\n${YELLOW}Cache Performance:${NC}"
curl -s http://localhost:3001/cache/stats | jq -r '
    "Total API calls: \(.statistics.total_analyses)",
    "Unique files: \(.statistics.unique_files)",
    "Average time: \(.statistics.avg_execution_time_ms)ms",
    "Cache size: \(.metadata.cache_size_bytes | tonumber / 1048576 | floor)MB"
'

echo -e "\n${GREEN}Complete Program Files scan finished!${NC}"
echo "Results saved in: $RESULTS_DIR"