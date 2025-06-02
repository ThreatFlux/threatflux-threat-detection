#!/bin/bash

# Direct Windows scanner using container paths

API_URL="http://localhost:3001/mcp"
RESULTS_DIR="windows_direct_scan"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
NC='\033[0m'

mkdir -p "$RESULTS_DIR"

echo -e "${BLUE}Windows Program Files Scanner${NC}"
echo "================================"

# Function to scan a single file
scan_file() {
    local filepath="$1"
    local filename=$(basename "$filepath")
    local app_path=$(echo "$filepath" | sed 's|/windows/||' | sed 's|/[^/]*$||')
    
    echo -ne "Scanning: $app_path/$filename... "
    
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
                    \"metadata\": true,
                    \"hashes\": true,
                    \"binary_info\": true,
                    \"threats\": true,
                    \"signatures\": true,
                    \"entropy\": true
                }
            }
        }")
    
    # Save response
    local safe_name=$(echo "$filename" | tr ' ' '_')
    echo "$response" > "$RESULTS_DIR/${safe_name}_${TIMESTAMP}.json"
    
    # Extract key information
    local threat_level=$(echo "$response" | jq -r '.result.content[0].text' 2>/dev/null | jq -r '.threats.threat_level // "Unknown"' 2>/dev/null)
    local is_signed=$(echo "$response" | jq -r '.result.content[0].text' 2>/dev/null | jq -r '.signatures.is_signed // false' 2>/dev/null)
    local entropy=$(echo "$response" | jq -r '.result.content[0].text' 2>/dev/null | jq -r '.entropy.overall_entropy // 0' 2>/dev/null)
    
    # Display result
    if [ "$threat_level" != "Clean" ] && [ "$threat_level" != "Unknown" ]; then
        echo -e "${RED}[THREAT: $threat_level]${NC}"
    elif [ "$is_signed" == "false" ]; then
        echo -e "${YELLOW}[Unsigned] (Entropy: $entropy)${NC}"
    else
        echo -e "${GREEN}[Clean/Signed]${NC}"
    fi
}

# Scan specific directories
echo -e "\n${YELLOW}[1/5] Scanning Steam Applications${NC}"
echo "--------------------------------"
docker exec file-scanner-http find "/windows/Program Files (x86)/Steam" -name "*.exe" -type f 2>/dev/null | head -10 | while read f; do
    scan_file "$f"
done

echo -e "\n${YELLOW}[2/5] Scanning Adobe Applications${NC}"
echo "--------------------------------"
docker exec file-scanner-http find "/windows/Program Files (x86)/Adobe" -name "*.exe" -type f 2>/dev/null | head -10 | while read f; do
    scan_file "$f"
done

echo -e "\n${YELLOW}[3/5] Scanning Microsoft Applications${NC}"
echo "--------------------------------"
docker exec file-scanner-http find "/windows/Program Files (x86)/Microsoft" -name "*.exe" -type f 2>/dev/null | head -10 | while read f; do
    scan_file "$f"
done

echo -e "\n${YELLOW}[4/5] Scanning AMD Software${NC}"
echo "--------------------------------"
docker exec file-scanner-http find "/windows/AMD" -name "*.exe" -type f 2>/dev/null | head -10 | while read f; do
    scan_file "$f"
done

echo -e "\n${YELLOW}[5/5] Scanning Other Applications${NC}"
echo "--------------------------------"
docker exec file-scanner-http find "/windows/Program Files (x86)" -maxdepth 2 -name "*.exe" -type f 2>/dev/null | grep -v -E "(Steam|Adobe|Microsoft|AMD)" | head -20 | while read f; do
    scan_file "$f"
done

# Generate summary report
echo -e "\n${BLUE}Security Analysis Summary${NC}"
echo "================================"

TOTAL=$(find "$RESULTS_DIR" -name "*_${TIMESTAMP}.json" | wc -l)
echo "Total files scanned: $TOTAL"

# Threat summary
echo -e "\n${RED}Threat Analysis:${NC}"
THREATS=$(find "$RESULTS_DIR" -name "*_${TIMESTAMP}.json" -exec jq -r '.result.content[0].text' {} \; 2>/dev/null | jq -r 'select(.threats.threat_level != "Clean") | "\(.file_path) - \(.threats.threat_level)"' 2>/dev/null | wc -l)
echo "Files with threats: $THREATS"

if [ $THREATS -gt 0 ]; then
    echo -e "\n${RED}Detected Threats:${NC}"
    find "$RESULTS_DIR" -name "*_${TIMESTAMP}.json" -exec jq -r '.result.content[0].text' {} \; 2>/dev/null | \
        jq -r 'select(.threats.threat_level != "Clean") | "\(.file_path | split("/") | .[-1]) - \(.threats.threat_level) - \(.threats.matches[0].rule_identifier // "Unknown")"' 2>/dev/null
fi

# Unsigned executables
echo -e "\n${YELLOW}Unsigned Executables:${NC}"
find "$RESULTS_DIR" -name "*_${TIMESTAMP}.json" -exec jq -r '.result.content[0].text' {} \; 2>/dev/null | \
    jq -r 'select(.signatures.is_signed == false) | .file_path | split("/") | .[-1]' 2>/dev/null | head -10

# High entropy files (possibly packed)
echo -e "\n${MAGENTA}High Entropy Files (>7.5):${NC}"
find "$RESULTS_DIR" -name "*_${TIMESTAMP}.json" -exec jq -r '.result.content[0].text' {} \; 2>/dev/null | \
    jq -r 'select(.entropy.overall_entropy > 7.5) | "\(.file_path | split("/") | .[-1]) - Entropy: \(.entropy.overall_entropy)"' 2>/dev/null

# Cache stats
echo -e "\n${BLUE}Performance Statistics:${NC}"
curl -s http://localhost:3001/cache/stats | jq -r '"Total analyses: \(.statistics.total_analyses)\nCache size: \(.metadata.cache_size_bytes | tonumber / 1048576 | floor)MB"'

echo -e "\n${GREEN}Scan complete!${NC}"