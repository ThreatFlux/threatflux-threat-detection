#!/bin/bash

# Background scanner for ALL 140K+ files in Windows Program Files
# Runs in background with nohup to complete the full scan

API_URL="http://localhost:3001/mcp"
RESULTS_DIR="complete_program_files_scan"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
MAX_FILE_SIZE=104857600  # 100MB limit
LOG_FILE="full_scan_${TIMESTAMP}.log"

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

echo -e "${BLUE}Starting FULL Program Files scan in background${NC}"
echo "Log file: $LOG_FILE"
echo "Results directory: $RESULTS_DIR"
echo "========================================"

# Get total file count
echo "$(date): Counting all files..." >> "$LOG_FILE"
TOTAL_FILES=$(docker exec file-scanner-http find "/windows/Program Files (x86)" -type f 2>/dev/null | wc -l)
echo "$(date): Total files found: $TOTAL_FILES" >> "$LOG_FILE"

if [ $TOTAL_FILES -eq 0 ]; then
    echo "No files found!" >> "$LOG_FILE"
    exit 1
fi

echo "$(date): Starting scan of $TOTAL_FILES files" >> "$LOG_FILE"
START_TIME=$(date +%s)

# Function to scan any file (same as original)
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
        echo "$(date): [$file_number/$total_files] SKIP $app_dir/$filename ($(($filesize/1048576))MB - too large)" >> "$LOG_FILE"
        return
    fi
    
    # Skip empty files
    if [ $filesize -eq 0 ]; then
        echo "$(date): [$file_number/$total_files] SKIP $app_dir/$filename (empty file)" >> "$LOG_FILE"
        return
    fi
    
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
    
    echo "$(date): [$file_number/$total_files] $app_dir/$filename - $status (${size_kb}KB)" >> "$LOG_FILE"
}

export -f scan_any_file
export API_URL RESULTS_DIR TIMESTAMP MAX_FILE_SIZE LOG_FILE

# Process all files with progress tracking
file_count=0
docker exec file-scanner-http find "/windows/Program Files (x86)" -type f 2>/dev/null | while read filepath; do
    file_count=$((file_count + 1))
    scan_any_file "$filepath" "$file_count" "$TOTAL_FILES"
    
    # Progress indicator every 5000 files
    if [ $((file_count % 5000)) -eq 0 ]; then
        echo "$(date): Progress: $file_count/$TOTAL_FILES files scanned ($(((file_count * 100) / TOTAL_FILES))%)" >> "$LOG_FILE"
        echo "Progress: $file_count/$TOTAL_FILES files scanned ($(((file_count * 100) / TOTAL_FILES))%)"
    fi
done

END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

# Final report
echo "$(date): SCAN COMPLETED!" >> "$LOG_FILE"
echo "$(date): Duration: $DURATION seconds" >> "$LOG_FILE"
echo "$(date): Files processed: $(find "$RESULTS_DIR" -name "*_${TIMESTAMP}.json" | wc -l)" >> "$LOG_FILE"

echo -e "${GREEN}Full scan complete! Check $LOG_FILE for results${NC}"