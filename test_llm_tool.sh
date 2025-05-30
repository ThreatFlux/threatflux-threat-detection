#!/bin/bash

echo "Testing LLM-Optimized File Analysis Tool"
echo "========================================"

# Start the MCP server in HTTP mode
echo "Starting MCP server with HTTP transport on port 3000..."
./target/release/file-scanner mcp-http --port 3000 &
SERVER_PID=$!

# Wait for server to start
sleep 2

# Test files
TEST_FILE1="/bin/ls"
TEST_FILE2="/bin/cat"
TEST_FILE3="/usr/bin/python3"

echo -e "\n1. List available tools (should show analyze_file and llm_analyze_file):"
echo "------------------------------------------------------------------------"
curl -s -X POST http://localhost:3000/mcp \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/list",
    "params": {}
  }' | jq '.result.tools[] | {name, description}'

echo -e "\n2. Basic LLM analysis of /bin/ls:"
echo "----------------------------------"
curl -s -X POST http://localhost:3000/tools/call \
  -H "Content-Type: application/json" \
  -d '{
    "name": "llm_analyze_file",
    "arguments": {
      "file_path": "'$TEST_FILE1'"
    }
  }' | jq -r '.content[0].text' | jq '.'

echo -e "\n3. LLM analysis with custom parameters:"
echo "---------------------------------------"
curl -s -X POST http://localhost:3000/tools/call \
  -H "Content-Type: application/json" \
  -d '{
    "name": "llm_analyze_file",
    "arguments": {
      "file_path": "'$TEST_FILE2'",
      "max_strings": 20,
      "max_imports": 10,
      "hex_pattern_size": 16,
      "suggest_yara_rule": true
    }
  }' | jq -r '.content[0].text' | jq '{md5, file_size, key_strings: .key_strings[:5], imports, entropy}'

echo -e "\n4. Extract YARA rule suggestion:"
echo "---------------------------------"
RESULT=$(curl -s -X POST http://localhost:3000/tools/call \
  -H "Content-Type: application/json" \
  -d '{
    "name": "llm_analyze_file",
    "arguments": {
      "file_path": "'$TEST_FILE3'",
      "max_strings": 15,
      "suggest_yara_rule": true
    }
  }' | jq -r '.content[0].text')

echo "$RESULT" | jq -r '.yara_rule_suggestion'

echo -e "\n5. Test token limiting (small limit):"
echo "-------------------------------------"
curl -s -X POST http://localhost:3000/tools/call \
  -H "Content-Type: application/json" \
  -d '{
    "name": "llm_analyze_file",
    "arguments": {
      "file_path": "'$TEST_FILE1'",
      "token_limit": 1000,
      "suggest_yara_rule": false
    }
  }' | jq -r '.content[0].text' | wc -c
echo "^ Character count (should be under 1000)"

echo -e "\n6. Compare with regular analyze_file (verbose):"
echo "-----------------------------------------------"
echo "Regular analyze_file output size:"
curl -s -X POST http://localhost:3000/tools/call \
  -H "Content-Type: application/json" \
  -d '{
    "name": "analyze_file",
    "arguments": {
      "file_path": "'$TEST_FILE1'",
      "metadata": true,
      "hashes": true,
      "strings": true,
      "binary_info": true
    }
  }' | jq -r '.content[0].text' | wc -c

echo -e "\nLLM-optimized output size:"
curl -s -X POST http://localhost:3000/tools/call \
  -H "Content-Type: application/json" \
  -d '{
    "name": "llm_analyze_file",
    "arguments": {
      "file_path": "'$TEST_FILE1'"
    }
  }' | jq -r '.content[0].text' | wc -c

echo -e "\n7. Test with non-existent file (error handling):"
echo "-------------------------------------------------"
curl -s -X POST http://localhost:3000/tools/call \
  -H "Content-Type: application/json" \
  -d '{
    "name": "llm_analyze_file",
    "arguments": {
      "file_path": "/non/existent/file.exe"
    }
  }' | jq '.'

# Kill the server
echo -e "\nStopping server..."
kill $SERVER_PID
wait $SERVER_PID 2>/dev/null

echo -e "\nLLM tool test completed!"