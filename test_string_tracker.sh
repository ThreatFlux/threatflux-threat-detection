#!/bin/bash

echo "Testing File Scanner String Tracker Feature"
echo "==========================================="

# Start the MCP server in HTTP mode
echo "Starting MCP server with HTTP transport on port 3000..."
./target/release/file-scanner mcp-http --port 3000 &
SERVER_PID=$!

# Wait for server to start
sleep 2

# Test files
TEST_FILE1="/bin/ls"
TEST_FILE2="/bin/cat"
TEST_FILE3="/bin/grep"

echo -e "\n1. Analyzing first file to populate string tracker:"
echo "---------------------------------------------------"
curl -s -X POST http://localhost:3000/tools/call \
  -H "Content-Type: application/json" \
  -d '{
    "name": "extract_file_strings",
    "arguments": {
      "file_path": "'$TEST_FILE1'",
      "min_length": 6
    }
  }' | jq -r '.content[0].text' | head -20

echo -e "\n2. Analyzing second file:"
echo "-------------------------"
curl -s -X POST http://localhost:3000/tools/call \
  -H "Content-Type: application/json" \
  -d '{
    "name": "extract_file_strings",
    "arguments": {
      "file_path": "'$TEST_FILE2'",
      "min_length": 6
    }
  }' | jq -r '.content[0].text' | head -20

echo -e "\n3. Analyzing third file:"
echo "------------------------"
curl -s -X POST http://localhost:3000/tools/call \
  -H "Content-Type: application/json" \
  -d '{
    "name": "extract_file_strings",
    "arguments": {
      "file_path": "'$TEST_FILE3'",
      "min_length": 6
    }
  }' | jq -r '.content[0].text' | head -20

echo -e "\n4. String statistics:"
echo "---------------------"
curl -s http://localhost:3000/strings/stats | jq '{
  total_unique_strings,
  total_occurrences,
  total_files_analyzed,
  category_distribution,
  length_distribution,
  most_common: .most_common[:10],
  suspicious_strings: .suspicious_strings[:5]
}'

echo -e "\n5. Search for strings containing 'lib':"
echo "---------------------------------------"
curl -s -X POST http://localhost:3000/strings/search \
  -H "Content-Type: application/json" \
  -d '{"query": "lib", "limit": 10}' | jq '.results[] | {value, total_occurrences, unique_files: .unique_files | length}'

echo -e "\n6. Get details for a specific string:"
echo "-------------------------------------"
# First, find a common string
COMMON_STRING=$(curl -s http://localhost:3000/strings/stats | jq -r '.most_common[0][0]')
echo "Getting details for: $COMMON_STRING"
curl -s -X POST http://localhost:3000/strings/details \
  -H "Content-Type: application/json" \
  -d "{\"value\": \"$COMMON_STRING\"}" | jq '{value, total_occurrences, unique_files: .unique_files | length, categories, entropy, is_suspicious}'

echo -e "\n7. Find related strings:"
echo "------------------------"
curl -s -X POST http://localhost:3000/strings/related \
  -H "Content-Type: application/json" \
  -d "{\"value\": \"$COMMON_STRING\", \"limit\": 5}" | jq '.related'

echo -e "\n8. Filter strings by criteria:"
echo "------------------------------"
echo "High entropy strings (entropy > 4.0):"
curl -s -X POST http://localhost:3000/strings/filter \
  -H "Content-Type: application/json" \
  -d '{
    "min_entropy": 4.0,
    "min_length": 10
  }' | jq '{
    total_unique_strings,
    high_entropy_strings: .high_entropy_strings[:10]
  }'

echo -e "\n9. Filter suspicious strings only:"
echo "----------------------------------"
curl -s -X POST http://localhost:3000/strings/filter \
  -H "Content-Type: application/json" \
  -d '{
    "suspicious_only": true
  }' | jq '{
    total_unique_strings,
    suspicious_strings: .suspicious_strings[:10]
  }'

echo -e "\n10. Filter by category (paths):"
echo "-------------------------------"
curl -s -X POST http://localhost:3000/strings/filter \
  -H "Content-Type: application/json" \
  -d '{
    "categories": ["path"]
  }' | jq '{
    total_unique_strings,
    most_common: .most_common[:10]
  }'

# Kill the server
echo -e "\nStopping server..."
kill $SERVER_PID
wait $SERVER_PID 2>/dev/null

echo -e "\nString tracker test completed!"