#!/bin/bash

echo "Testing File Scanner Cache Feature"
echo "=================================="

# Start the MCP server in HTTP mode
echo "Starting MCP server with HTTP transport on port 3000..."
./target/release/file-scanner mcp-http --port 3000 &
SERVER_PID=$!

# Wait for server to start
sleep 2

# Test file paths
TEST_FILE="/bin/ls"

echo -e "\n1. First analysis (will be cached):"
echo "-----------------------------------"
curl -s -X POST http://localhost:3000/tools/call \
  -H "Content-Type: application/json" \
  -d '{
    "name": "calculate_file_hashes",
    "arguments": {
      "file_path": "'$TEST_FILE'"
    }
  }' | jq -r '.content[0].text'

echo -e "\n2. Second analysis (should use cache):"
echo "--------------------------------------"
curl -s -X POST http://localhost:3000/tools/call \
  -H "Content-Type: application/json" \
  -d '{
    "name": "calculate_file_hashes",
    "arguments": {
      "file_path": "'$TEST_FILE'"
    }
  }' | jq -r '.content[0].text'

echo -e "\n3. Cache statistics:"
echo "--------------------"
curl -s http://localhost:3000/cache/stats | jq '.'

echo -e "\n4. List cache entries:"
echo "----------------------"
curl -s http://localhost:3000/cache/list | jq '.entries[] | {file_path, tool_name, timestamp}'

echo -e "\n5. Testing different tool (analyze_binary_file):"
echo "------------------------------------------------"
curl -s -X POST http://localhost:3000/tools/call \
  -H "Content-Type: application/json" \
  -d '{
    "name": "analyze_binary_file",
    "arguments": {
      "file_path": "'$TEST_FILE'"
    }
  }' | jq -r '.content[0].text' | head -20

echo -e "\n6. Updated cache statistics:"
echo "----------------------------"
curl -s http://localhost:3000/cache/stats | jq '.'

echo -e "\n7. Search cache for specific tool:"
echo "----------------------------------"
curl -s -X POST http://localhost:3000/cache/search \
  -H "Content-Type: application/json" \
  -d '{
    "tool_name": "calculate_file_hashes"
  }' | jq '.results[] | {file_path, tool_name, execution_time_ms}'

echo -e "\n8. Clear cache:"
echo "---------------"
curl -s -X POST http://localhost:3000/cache/clear | jq '.'

echo -e "\n9. Cache statistics after clear:"
echo "--------------------------------"
curl -s http://localhost:3000/cache/stats | jq '.'

# Kill the server
echo -e "\nStopping server..."
kill $SERVER_PID
wait $SERVER_PID 2>/dev/null

echo -e "\nCache test completed!"