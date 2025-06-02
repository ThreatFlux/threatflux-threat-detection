# File Scanner Analysis Reports

This document summarizes the analysis reports generated for review.

## Generated Reports

### Successfully Generated MCP API Reports
After fixing the port (3001) and file path issues (Docker container uses `/data/` path):

- **crypto_miner_llm_mcp_final.json** (2.4KB) - LLM-optimized analysis of the Go crypto miner
- **c_advanced_llm_mcp_analysis.json** (8 lines) - LLM-optimized analysis of the C malware simulator
- **c_advanced_comprehensive_mcp_final.json** (336KB) - Complete comprehensive analysis with all features

### Direct CLI Analysis Reports
Generated using the file-scanner CLI directly:

- **crypto_miner_direct_analysis.json** (2.9KB) - Basic analysis of the Go-based crypto miner
- **c_advanced_direct_analysis.json** (87KB) - Detailed analysis with strings and hex dump

### Issue Resolution
The initial API calls failed because:
1. Wrong port - Docker container maps port 3000 to 3001
2. Wrong file paths - Docker container only has access to `/tmp` (mounted as `/data`)
3. Solution: Copy files to `/tmp/` and use `/data/` paths in API calls

## Key Differences

### LLM-Optimized Reports (`llm_analyze_file`)
- Token-limited output (default 25K characters)
- Only MD5 hash (not SHA256/SHA512/BLAKE3)
- Prioritized string selection (most relevant for detection)
- Automatic YARA rule generation
- Focused on malware detection indicators

### Comprehensive Reports (`analyze_file`)
- Full cryptographic hash set (MD5, SHA256, SHA512, BLAKE3)
- Complete string extraction (all strings found)
- Detailed binary format analysis
- Entropy analysis by section
- Threat detection with YARA-X
- Behavioral pattern analysis
- Vulnerability detection
- Symbol and function analysis

## Viewing the Reports

To view the reports in a formatted way:

```bash
# Pretty print the JSON reports
jq '.' crypto_miner_analysis_full.json | less
jq '.' c_advanced_binary_analysis_full.json | less
jq '.' crypto_miner_analysis_comprehensive.json | less
jq '.' c_advanced_binary_analysis_comprehensive.json | less
```

## Report Locations

All reports are saved in: `/home/vtriple/file-scanner/`

- crypto_miner_analysis_full.json
- c_advanced_binary_analysis_full.json
- crypto_miner_analysis_comprehensive.json
- c_advanced_binary_analysis_comprehensive.json

These reports provide both quick triage capabilities (LLM-optimized) and deep technical analysis (comprehensive) for security research and threat detection.