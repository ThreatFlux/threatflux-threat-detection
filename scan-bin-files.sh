#!/bin/bash

# Fast parallel file scanner for /bin directory
# Uses GNU parallel for maximum performance

API_URL="http://localhost:3001/mcp"
CONCURRENT_JOBS=10
RESULTS_DIR="scan_results"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Create results directory
mkdir -p "$RESULTS_DIR"

# Function to scan a single file
scan_file() {
    local file="$1"
    local filename=$(basename "$file")
    local output_file="$RESULTS_DIR/${filename}_${TIMESTAMP}.json"
    
    # Skip if not a regular file
    if [ ! -f "$file" ]; then
        return
    fi
    
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
            "metadata": true,
            "hashes": true,
            "binary_info": true
        }
    }
}
EOF
)
    
    # Send request and save response
    echo "Scanning: $file"
    curl -s -X POST "$API_URL" \
        -H "Content-Type: application/json" \
        -d "$request" \
        -o "$output_file" 2>/dev/null
    
    # Check if successful
    if [ $? -eq 0 ] && [ -s "$output_file" ]; then
        echo "✓ Completed: $file"
    else
        echo "✗ Failed: $file"
        rm -f "$output_file"
    fi
}

# Export function for parallel execution
export -f scan_file
export API_URL RESULTS_DIR TIMESTAMP

echo "Starting parallel scan of /bin directory..."
echo "Using $CONCURRENT_JOBS concurrent jobs"
echo "Results will be saved to: $RESULTS_DIR"
echo "----------------------------------------"

# Count total files (follow symlink)
TOTAL_FILES=$(find /usr/bin -maxdepth 1 -type f 2>/dev/null | wc -l)
echo "Total files to scan: $TOTAL_FILES"
echo "----------------------------------------"

# Start timer
START_TIME=$(date +%s)

# Run parallel scan (limiting to first 50 files for demo)
if command -v parallel &> /dev/null; then
    # Use GNU parallel if available
    find /usr/bin -maxdepth 1 -type f 2>/dev/null | head -50 | \
        parallel -j $CONCURRENT_JOBS --progress scan_file {}
else
    # Fallback to xargs
    echo "Note: Install GNU parallel for better performance"
    find /usr/bin -maxdepth 1 -type f 2>/dev/null | head -50 | \
        xargs -P $CONCURRENT_JOBS -I {} bash -c 'scan_file "$@"' _ {}
fi

# End timer
END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

echo "----------------------------------------"
echo "Scan completed in $DURATION seconds"
echo "Results saved to: $RESULTS_DIR"

# Get cache statistics
echo "----------------------------------------"
echo "Cache statistics:"
curl -s http://localhost:3001/cache/stats | jq -r '
    "Total analyses: \(.statistics.total_analyses)",
    "Unique files: \(.statistics.unique_files)", 
    "Avg execution time: \(.statistics.avg_execution_time_ms)ms",
    "Cache size: \(.metadata.cache_size_bytes) bytes"
'

# Summary report
echo "----------------------------------------"
SUCCESSFUL=$(find "$RESULTS_DIR" -name "*_${TIMESTAMP}.json" 2>/dev/null | wc -l)
echo "Successfully scanned: $SUCCESSFUL files"
echo "Failed: $((TOTAL_FILES - SUCCESSFUL)) files"

# Optional: Create summary file
SUMMARY_FILE="$RESULTS_DIR/summary_${TIMESTAMP}.txt"
{
    echo "Scan Summary - $(date)"
    echo "========================"
    echo "Total files: $TOTAL_FILES"
    echo "Successful: $SUCCESSFUL"
    echo "Failed: $((TOTAL_FILES - SUCCESSFUL))"
    echo "Duration: $DURATION seconds"
    if [ $DURATION -gt 0 ]; then
        echo "Rate: $(echo "scale=2; $SUCCESSFUL / $DURATION" | bc) files/sec"
    else
        echo "Rate: N/A (too fast to measure)"
    fi
    echo ""
    echo "Files scanned:"
    find "$RESULTS_DIR" -name "*_${TIMESTAMP}.json" -exec basename {} \; | sed 's/_[0-9]*_[0-9]*\.json$//' | sort
} > "$SUMMARY_FILE"

echo "Summary saved to: $SUMMARY_FILE"