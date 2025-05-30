#!/bin/bash

echo "Testing Unified File Scanner MCP Tool"
echo "====================================="

# Start the MCP server in HTTP mode
echo "Starting MCP server with HTTP transport on port 3000..."
./target/release/file-scanner mcp-http --port 3000 &
SERVER_PID=$!

# Wait for server to start
sleep 2

# Test file
TEST_FILE="/bin/ls"

echo -e "\n1. List available tools (should show only 'analyze_file'):"
echo "-----------------------------------------------------------"
curl -s -X POST http://localhost:3000/mcp \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/list",
    "params": {}
  }' | jq '.result.tools'

echo -e "\n2. Basic analysis (metadata + hashes):"
echo "--------------------------------------"
curl -s -X POST http://localhost:3000/tools/call \
  -H "Content-Type: application/json" \
  -d '{
    "name": "analyze_file",
    "arguments": {
      "file_path": "'$TEST_FILE'",
      "metadata": true,
      "hashes": true
    }
  }' | jq -r '.content[0].text' | jq '{file_path, metadata, hashes}'

echo -e "\n3. String extraction:"
echo "---------------------"
curl -s -X POST http://localhost:3000/tools/call \
  -H "Content-Type: application/json" \
  -d '{
    "name": "analyze_file",
    "arguments": {
      "file_path": "'$TEST_FILE'",
      "strings": true,
      "min_string_length": 8
    }
  }' | jq -r '.content[0].text' | jq '{file_path, strings: .strings[:10]}'

echo -e "\n4. Binary analysis:"
echo "-------------------"
curl -s -X POST http://localhost:3000/tools/call \
  -H "Content-Type: application/json" \
  -d '{
    "name": "analyze_file",
    "arguments": {
      "file_path": "'$TEST_FILE'",
      "binary_info": true,
      "symbols": true
    }
  }' | jq -r '.content[0].text' | jq '{file_path, binary_info: .binary_info.file_format, symbols: .symbols.symbol_count}'

echo -e "\n5. Security analysis:"
echo "---------------------"
curl -s -X POST http://localhost:3000/tools/call \
  -H "Content-Type: application/json" \
  -d '{
    "name": "analyze_file",
    "arguments": {
      "file_path": "'$TEST_FILE'",
      "threats": true,
      "vulnerabilities": true,
      "entropy": true
    }
  }' | jq -r '.content[0].text' | jq '{file_path, threats: .threats.threat_level, vulnerabilities: .vulnerabilities.vulnerability_count, entropy: .entropy.overall_entropy}'

echo -e "\n6. Comprehensive analysis (all features):"
echo "-----------------------------------------"
curl -s -X POST http://localhost:3000/tools/call \
  -H "Content-Type: application/json" \
  -d '{
    "name": "analyze_file",
    "arguments": {
      "file_path": "'$TEST_FILE'",
      "metadata": true,
      "hashes": true,
      "strings": true,
      "hex_dump": true,
      "hex_dump_size": 128,
      "binary_info": true,
      "signatures": true,
      "symbols": true,
      "control_flow": true,
      "vulnerabilities": true,
      "code_quality": true,
      "dependencies": true,
      "entropy": true,
      "disassembly": true,
      "threats": true,
      "behavioral": true,
      "yara_indicators": true
    }
  }' | jq -r '.content[0].text' | jq 'keys'

# Kill the server
echo -e "\nStopping server..."
kill $SERVER_PID
wait $SERVER_PID 2>/dev/null

echo -e "\nUnified tool test completed!"