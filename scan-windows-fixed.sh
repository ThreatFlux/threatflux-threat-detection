#!/bin/bash

# Fixed Windows Program Files Scanner
# Uses container mount path /windows

API_URL="http://localhost:3001/mcp"
CONCURRENT_JOBS=8
RESULTS_DIR="windows_scan_results"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
WINDOWS_PATH="/windows/Program Files (x86)"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

mkdir -p "$RESULTS_DIR"

echo -e "${BLUE}Windows Program Files Scanner${NC}"
echo "================================"
echo "Scanning: $WINDOWS_PATH"
echo "================================"

# Find all executables
echo -e "\n${YELLOW}Scanning Windows Applications...${NC}"

find "$WINDOWS_PATH" -name "*.exe" -type f 2>/dev/null | head -30 | while read filepath; do
    filename=$(basename "$filepath")
    app_name=$(echo "$filepath" | sed 's|.*/Program Files (x86)/||' | cut -d'/' -f1)
    
    echo -ne "Scanning $app_name/$filename... "
    
    # Create request
    request=$(cat <<EOF
{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {
        "name": "analyze_file",
        "arguments": {
            "file_path": "$filepath",
            "metadata": true,
            "hashes": true,
            "binary_info": true,
            "threats": true,
            "signatures": true
        }
    }
}
EOF
)
    
    # Send request and save
    output_file="$RESULTS_DIR/${app_name}_${filename}_${TIMESTAMP}.json"
    
    if curl -s -X POST "$API_URL" \
        -H "Content-Type: application/json" \
        -d "$request" \
        -o "$output_file" 2>/dev/null; then
        
        # Check for threats
        threats=$(jq -r '.result.content[0].text | fromjson | .threats.threat_level // "Unknown"' "$output_file" 2>/dev/null)
        signed=$(jq -r '.result.content[0].text | fromjson | .signatures.is_signed // false' "$output_file" 2>/dev/null)
        
        if [ "$threats" != "Clean" ] && [ "$threats" != "Unknown" ]; then
            echo -e "${RED}[THREAT: $threats]${NC}"
        elif [ "$signed" == "false" ]; then
            echo -e "${YELLOW}[Unsigned]${NC}"
        else
            echo -e "${GREEN}[Clean]${NC}"
        fi
    else
        echo -e "${RED}[Failed]${NC}"
    fi
done

# Summary
echo -e "\n${BLUE}Scan Summary${NC}"
echo "================================"
TOTAL=$(find "$RESULTS_DIR" -name "*_${TIMESTAMP}.json" | wc -l)
echo "Total files scanned: $TOTAL"

# Show threats
echo -e "\n${RED}Threats Detected:${NC}"
find "$RESULTS_DIR" -name "*_${TIMESTAMP}.json" -exec jq -r '.result.content[0].text | fromjson | select(.threats.threat_level != "Clean") | "\(.file_path) - \(.threats.threat_level)"' {} \; 2>/dev/null

# Show unsigned executables
echo -e "\n${YELLOW}Unsigned Executables:${NC}"
find "$RESULTS_DIR" -name "*_${TIMESTAMP}.json" -exec jq -r '.result.content[0].text | fromjson | select(.signatures.is_signed == false) | .file_path' {} \; 2>/dev/null | head -10

echo -e "\n${GREEN}Scan complete!${NC}"