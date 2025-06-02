#!/bin/bash

# Parallel scanner for ALL Windows Program Files
# Submits multiple files simultaneously for faster processing

API_URL="http://localhost:3001/mcp"
RESULTS_DIR="parallel_program_files_scan"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
MAX_FILE_SIZE=104857600  # 100MB limit
CONCURRENT_JOBS=20  # Process 20 files simultaneously
LOG_FILE="parallel_scan_${TIMESTAMP}.log"

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

echo -e "${BLUE}Parallel Windows Program Files Scanner${NC}"
echo "Concurrent jobs: $CONCURRENT_JOBS (moderate load)"
echo "Log file: $LOG_FILE"
echo "Results directory: $RESULTS_DIR"
echo "========================================"

# Function to scan a single file
scan_file_parallel() {
    local filepath="$1"
    local filename=$(basename "$filepath")
    local extension="${filename##*.}"
    local app_dir=$(echo "$filepath" | sed 's|/windows/Program Files (x86)/||' | cut -d'/' -f1)
    
    # Check file size
    local filesize=$(docker exec file-scanner-http stat -c%s "$filepath" 2>/dev/null || echo 0)
    if [ $filesize -gt $MAX_FILE_SIZE ]; then
        echo "$(date): SKIP $app_dir/$filename ($(($filesize/1048576))MB - too large)" >> "$LOG_FILE"
        return
    fi
    
    # Skip empty files
    if [ $filesize -eq 0 ]; then
        echo "$(date): SKIP $app_dir/$filename (empty)" >> "$LOG_FILE"
        return
    fi
    
    # Determine analysis options
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
    
    # Log result
    local status=""
    local size_kb=$((filesize/1024))
    
    if [ "$threat_level" != "Clean" ] && [ "$threat_level" != "null" ]; then
        status="THREAT:$threat_level"
    elif [ "$is_signed" == "false" ] && [[ "$extension" =~ ^(exe|dll|sys|ocx)$ ]]; then
        if [ $(echo "$entropy > 7.5" | bc -l 2>/dev/null || echo 0) -eq 1 ]; then
            status="Unsigned/Packed"
        else
            status="Unsigned"
        fi
    else
        status="Clean"
    fi
    
    echo "$(date): $app_dir/$filename - $status (${size_kb}KB)" >> "$LOG_FILE"
}

export -f scan_file_parallel
export API_URL RESULTS_DIR TIMESTAMP MAX_FILE_SIZE LOG_FILE

# Get total file count
echo "$(date): Counting all files..." >> "$LOG_FILE"
TOTAL_FILES=$(docker exec file-scanner-http find "/windows/Program Files (x86)" -type f 2>/dev/null | wc -l)
echo "$(date): Total files found: $TOTAL_FILES" >> "$LOG_FILE"

if [ $TOTAL_FILES -eq 0 ]; then
    echo "No files found!" >> "$LOG_FILE"
    exit 1
fi

echo "$(date): Starting parallel scan with $CONCURRENT_JOBS concurrent jobs" >> "$LOG_FILE"
echo -e "${GREEN}Processing $TOTAL_FILES files with $CONCURRENT_JOBS parallel jobs (moderate load)${NC}"

START_TIME=$(date +%s)

# Process files in parallel using xargs
docker exec file-scanner-http find "/windows/Program Files (x86)" -type f 2>/dev/null | \
    xargs -n 1 -P $CONCURRENT_JOBS -I {} bash -c 'scan_file_parallel "{}"'

END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

# Generate final report
echo "$(date): PARALLEL SCAN COMPLETED!" >> "$LOG_FILE"
echo "$(date): Duration: $DURATION seconds" >> "$LOG_FILE"

SCANNED_COUNT=$(find "$RESULTS_DIR" -name "*_${TIMESTAMP}.json" | wc -l)
echo "$(date): Files processed: $SCANNED_COUNT" >> "$LOG_FILE"

# Count threats
THREATS=$(find "$RESULTS_DIR" -name "*_${TIMESTAMP}.json" -exec jq -r '.result.content[0].text' {} \; 2>/dev/null | \
    jq -r 'select(.threats.threat_level != "Clean" and .threats.threat_level != null) | .file_path' 2>/dev/null | wc -l)

echo "$(date): Threats detected: $THREATS" >> "$LOG_FILE"

# Performance summary
echo -e "\n${BLUE}=== PARALLEL SCAN COMPLETE ===${NC}"
echo "Files processed: $SCANNED_COUNT / $TOTAL_FILES"
echo "Duration: $DURATION seconds"
echo "Rate: $((SCANNED_COUNT / DURATION)) files/second"
echo "Threats detected: $THREATS"
echo "Results in: $RESULTS_DIR"
echo "Log file: $LOG_FILE"