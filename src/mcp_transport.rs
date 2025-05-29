use anyhow::Result;
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{Json as AxumJson, Sse},
    routing::{get, post},
    Router,
};
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::net::TcpListener;
use tokio_stream::{wrappers::UnboundedReceiverStream, Stream};
use tower::ServiceBuilder;
use uuid::Uuid;

use crate::mcp_server::FileScannerMcp;

#[derive(Clone)]
pub struct McpServerState {
    handler: FileScannerMcp,
    sse_clients: Arc<Mutex<HashMap<String, tokio::sync::mpsc::UnboundedSender<SseEvent>>>>,
}

#[derive(Clone, Debug)]
pub struct SseEvent {
    pub id: Option<String>,
    pub event: Option<String>,
    pub data: String,
}

#[derive(Deserialize)]
pub struct SseQuery {
    pub client_id: Option<String>,
}

#[derive(Deserialize, Serialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub id: Option<Value>,
    pub method: String,
    pub params: Option<Value>,
}

#[derive(Deserialize, Serialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    pub id: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

#[derive(Deserialize, Serialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    pub data: Option<Value>,
}

#[derive(Deserialize)]
struct ToolCallParams {
    name: String,
    arguments: HashMap<String, Value>,
}

pub struct McpTransportServer {
    handler: FileScannerMcp,
}

impl McpTransportServer {
    pub fn new() -> Self {
        Self {
            handler: FileScannerMcp,
        }
    }

    /// Run MCP server with stdio transport
    pub async fn run_stdio(&self) -> Result<()> {
        use rmcp::ServerHandler;
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        
        let info = self.handler.get_info();
        eprintln!("MCP Server starting: {}", info.server_info.name);
        eprintln!("Version: {}", info.server_info.version);
        eprintln!("Protocol: {}", info.protocol_version);
        eprintln!("Use with: npx @modelcontextprotocol/inspector ./target/release/file-scanner mcp-stdio");
        
        // Use tokio async IO for proper MCP stdio transport
        let stdin = tokio::io::stdin();
        let mut stdout = tokio::io::stdout();
        let mut reader = BufReader::new(stdin);
        let mut line = String::new();
        
        // Process JSON-RPC messages from stdin
        loop {
            line.clear();
            match reader.read_line(&mut line).await {
                Ok(0) => break, // EOF
                Ok(_) => {
                    let trimmed = line.trim();
                    if trimmed.is_empty() {
                        continue;
                    }
                    
                    match serde_json::from_str::<JsonRpcRequest>(trimmed) {
                        Ok(request) => {
                            let response = self.handle_jsonrpc_request(request).await;
                            let response_str = serde_json::to_string(&response)?;
                            stdout.write_all(response_str.as_bytes()).await?;
                            stdout.write_all(b"\n").await?;
                            stdout.flush().await?;
                        }
                        Err(e) => {
                            eprintln!("Parse error: {}", e);
                            let error = JsonRpcResponse {
                                jsonrpc: "2.0".to_string(),
                                id: None,
                                result: None,
                                error: Some(JsonRpcError {
                                    code: -32700,
                                    message: format!("Parse error: {}", e),
                                    data: None,
                                }),
                            };
                            let error_str = serde_json::to_string(&error)?;
                            stdout.write_all(error_str.as_bytes()).await?;
                            stdout.write_all(b"\n").await?;
                            stdout.flush().await?;
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Read error: {}", e);
                    break;
                }
            }
        }
        
        Ok(())
    }

    /// Run MCP server with HTTP transport
    pub async fn run_http(&self, port: u16) -> Result<()> {
        let state = McpServerState {
            handler: self.handler.clone(),
            sse_clients: Arc::new(Mutex::new(HashMap::new())),
        };

        let app = Router::new()
            .route("/mcp", post(handle_mcp_http_request))
            .route("/health", get(health_check))
            .route("/initialize", post(handle_initialize))
            .route("/tools/list", post(handle_tools_list))
            .route("/tools/call", post(handle_tools_call))
            .with_state(state)
            .layer(
                ServiceBuilder::new()
                    .layer(axum::middleware::from_fn(cors_middleware))
            );

        let listener = TcpListener::bind(format!("0.0.0.0:{}", port)).await?;
        println!("MCP HTTP server listening on http://localhost:{}", port);
        println!("Endpoints:");
        println!("  - POST /mcp - MCP JSON-RPC endpoint");
        println!("  - GET /health - Health check");
        println!("  - POST /initialize - Initialize MCP session");
        println!("  - POST /tools/list - List available tools");
        println!("  - POST /tools/call - Call a tool");
        println!();
        println!("Test with MCP Inspector:");
        println!("  npx @modelcontextprotocol/inspector http://localhost:{}/mcp", port);
        
        axum::serve(listener, app).await?;
        Ok(())
    }

    /// Run MCP server with SSE transport
    pub async fn run_sse(&self, port: u16) -> Result<()> {
        let state = McpServerState {
            handler: self.handler.clone(),
            sse_clients: Arc::new(Mutex::new(HashMap::new())),
        };

        let app = Router::new()
            .route("/sse", get(handle_sse_connection))
            .route("/mcp", post(handle_mcp_sse_request))
            .route("/health", get(health_check))
            .with_state(state)
            .layer(
                ServiceBuilder::new()
                    .layer(axum::middleware::from_fn(cors_middleware))
            );

        let listener = TcpListener::bind(format!("0.0.0.0:{}", port)).await?;
        println!("MCP SSE server listening on http://localhost:{}", port);
        println!("Endpoints:");
        println!("  - GET /sse - SSE connection endpoint");
        println!("  - POST /mcp - MCP JSON-RPC over SSE");
        println!("  - GET /health - Health check");
        println!();
        println!("Test with MCP Inspector:");
        println!("  npx @modelcontextprotocol/inspector http://localhost:{}/sse", port);
        
        axum::serve(listener, app).await?;
        Ok(())
    }

    async fn handle_jsonrpc_request(&self, request: JsonRpcRequest) -> JsonRpcResponse {
        use rmcp::ServerHandler;
        
        match request.method.as_str() {
            "initialize" => {
                let info = self.handler.get_info();
                JsonRpcResponse {
                    jsonrpc: "2.0".to_string(),
                    id: request.id,
                    result: Some(json!({
                        "protocolVersion": "2024-11-05",
                        "serverInfo": info.server_info,
                        "capabilities": info.capabilities
                    })),
                    error: None,
                }
            }
            "tools/list" => {
                JsonRpcResponse {
                    jsonrpc: "2.0".to_string(),
                    id: request.id,
                    result: Some(json!({
                        "tools": [
                            {
                                "name": "calculate_file_hashes",
                                "description": "Calculate cryptographic hashes (MD5, SHA256, SHA512, BLAKE3) for a file",
                                "inputSchema": {
                                    "type": "object",
                                    "properties": {
                                        "file_path": {
                                            "type": "string",
                                            "description": "Path to the file to hash"
                                        }
                                    },
                                    "required": ["file_path"]
                                }
                            },
                            {
                                "name": "extract_file_strings",
                                "description": "Extract ASCII and Unicode strings from a file",
                                "inputSchema": {
                                    "type": "object",
                                    "properties": {
                                        "file_path": {
                                            "type": "string",
                                            "description": "Path to the file to extract strings from"
                                        },
                                        "min_length": {
                                            "type": "integer",
                                            "description": "Minimum string length",
                                            "default": 4
                                        }
                                    },
                                    "required": ["file_path"]
                                }
                            },
                            {
                                "name": "hex_dump_file",
                                "description": "Generate a hex dump of a file or part of a file",
                                "inputSchema": {
                                    "type": "object",
                                    "properties": {
                                        "file_path": {
                                            "type": "string",
                                            "description": "Path to the file to hex dump"
                                        },
                                        "size": {
                                            "type": "integer",
                                            "description": "Number of bytes to dump",
                                            "default": 256
                                        },
                                        "offset": {
                                            "type": "integer",
                                            "description": "Offset from start of file",
                                            "default": 0
                                        }
                                    },
                                    "required": ["file_path"]
                                }
                            },
                            {
                                "name": "analyze_binary_file",
                                "description": "Analyze binary file format (PE, ELF, Mach-O) and extract metadata",
                                "inputSchema": {
                                    "type": "object",
                                    "properties": {
                                        "file_path": {
                                            "type": "string",
                                            "description": "Path to the binary file to analyze"
                                        }
                                    },
                                    "required": ["file_path"]
                                }
                            },
                            {
                                "name": "get_file_metadata",
                                "description": "Extract file system metadata including timestamps, permissions, and file type",
                                "inputSchema": {
                                    "type": "object",
                                    "properties": {
                                        "file_path": {
                                            "type": "string",
                                            "description": "Path to the file to get metadata for"
                                        }
                                    },
                                    "required": ["file_path"]
                                }
                            },
                            {
                                "name": "verify_file_signatures",
                                "description": "Verify digital signatures on a file",
                                "inputSchema": {
                                    "type": "object",
                                    "properties": {
                                        "file_path": {
                                            "type": "string",
                                            "description": "Path to the file to verify signatures for"
                                        }
                                    },
                                    "required": ["file_path"]
                                }
                            },
                            {
                                "name": "analyze_function_symbols",
                                "description": "Analyze function symbols and cross-references in a binary file",
                                "inputSchema": {
                                    "type": "object",
                                    "properties": {
                                        "file_path": {
                                            "type": "string",
                                            "description": "Path to the binary file to analyze"
                                        }
                                    },
                                    "required": ["file_path"]
                                }
                            },
                            {
                                "name": "analyze_control_flow_graph",
                                "description": "Analyze control flow graphs, basic blocks, and complexity metrics in a binary file",
                                "inputSchema": {
                                    "type": "object",
                                    "properties": {
                                        "file_path": {
                                            "type": "string",
                                            "description": "Path to the binary file to analyze"
                                        }
                                    },
                                    "required": ["file_path"]
                                }
                            },
                            {
                                "name": "detect_vulnerabilities",
                                "description": "Detect security vulnerabilities using static analysis patterns and rules",
                                "inputSchema": {
                                    "type": "object",
                                    "properties": {
                                        "file_path": {
                                            "type": "string",
                                            "description": "Path to the binary file to analyze for vulnerabilities"
                                        }
                                    },
                                    "required": ["file_path"]
                                }
                            },
                            {
                                "name": "analyze_code_quality",
                                "description": "Analyze code quality metrics including complexity, maintainability, and technical debt",
                                "inputSchema": {
                                    "type": "object",
                                    "properties": {
                                        "file_path": {
                                            "type": "string",
                                            "description": "Path to the binary file to analyze for code quality"
                                        }
                                    },
                                    "required": ["file_path"]
                                }
                            },
                            {
                                "name": "analyze_dependencies",
                                "description": "Analyze library dependencies, detect vulnerable libraries, and check license compliance",
                                "inputSchema": {
                                    "type": "object",
                                    "properties": {
                                        "file_path": {
                                            "type": "string",
                                            "description": "Path to the binary file to analyze for dependencies"
                                        }
                                    },
                                    "required": ["file_path"]
                                }
                            },
                            {
                                "name": "analyze_entropy_patterns",
                                "description": "Analyze entropy patterns to detect packing, encryption, and obfuscation techniques",
                                "inputSchema": {
                                    "type": "object",
                                    "properties": {
                                        "file_path": {
                                            "type": "string",
                                            "description": "Path to the file to analyze for entropy patterns"
                                        }
                                    },
                                    "required": ["file_path"]
                                }
                            },
                            {
                                "name": "disassemble_code",
                                "description": "Disassemble binary code with multi-architecture support and advanced instruction analysis",
                                "inputSchema": {
                                    "type": "object",
                                    "properties": {
                                        "file_path": {
                                            "type": "string",
                                            "description": "Path to the binary file to disassemble"
                                        }
                                    },
                                    "required": ["file_path"]
                                }
                            },
                            {
                                "name": "detect_threats",
                                "description": "Detect threats and malware using YARA-X rules with comprehensive pattern matching",
                                "inputSchema": {
                                    "type": "object",
                                    "properties": {
                                        "file_path": {
                                            "type": "string",
                                            "description": "Path to the file to analyze for threats"
                                        }
                                    },
                                    "required": ["file_path"]
                                }
                            },
                            {
                                "name": "analyze_behavioral_patterns",
                                "description": "Analyze behavioral patterns including anti-analysis, persistence, and evasion techniques",
                                "inputSchema": {
                                    "type": "object",
                                    "properties": {
                                        "file_path": {
                                            "type": "string",
                                            "description": "Path to the file to analyze for behavioral patterns"
                                        }
                                    },
                                    "required": ["file_path"]
                                }
                            }
                        ]
                    })),
                    error: None,
                }
            }
            "tools/call" => {
                if let Some(params) = request.params {
                    if let Ok(tool_call) = serde_json::from_value::<ToolCallParams>(params) {
                        let result = self.handle_tool_call(tool_call).await;
                        JsonRpcResponse {
                            jsonrpc: "2.0".to_string(),
                            id: request.id,
                            result: Some(result),
                            error: None,
                        }
                    } else {
                        JsonRpcResponse {
                            jsonrpc: "2.0".to_string(),
                            id: request.id,
                            result: None,
                            error: Some(JsonRpcError {
                                code: -32602,
                                message: "Invalid params".to_string(),
                                data: None,
                            }),
                        }
                    }
                } else {
                    JsonRpcResponse {
                        jsonrpc: "2.0".to_string(),
                        id: request.id,
                        result: None,
                        error: Some(JsonRpcError {
                            code: -32600,
                            message: "Invalid Request".to_string(),
                            data: None,
                        }),
                    }
                }
            }
            _ => JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                id: request.id,
                result: None,
                error: Some(JsonRpcError {
                    code: -32601,
                    message: "Method not found".to_string(),
                    data: None,
                }),
            },
        }
    }

    async fn handle_tool_call(&self, params: ToolCallParams) -> Value {
        use crate::{
            binary_parser::parse_binary,
            hash::calculate_all_hashes,
            hexdump::{format_hex_dump_text, generate_hex_dump, HexDumpOptions},
            metadata::FileMetadata,
            signature::verify_signature,
            strings::extract_strings,
        };
        use std::path::PathBuf;

        match params.name.as_str() {
            "calculate_file_hashes" => {
                if let Some(file_path) = params.arguments.get("file_path").and_then(|v| v.as_str()) {
                    let path = PathBuf::from(file_path);
                    if !path.exists() {
                        return json!({"content": [{"type": "text", "text": format!("Error: File does not exist: {}", file_path)}]});
                    }
                    match calculate_all_hashes(&path).await {
                        Ok(hashes) => json!({"content": [{"type": "text", "text": serde_json::to_string_pretty(&hashes).unwrap_or_default()}]}),
                        Err(e) => json!({"content": [{"type": "text", "text": format!("Error: {}", e)}]}),
                    }
                } else {
                    json!({"content": [{"type": "text", "text": "Error: Missing file_path parameter"}]})
                }
            }
            "extract_file_strings" => {
                if let Some(file_path) = params.arguments.get("file_path").and_then(|v| v.as_str()) {
                    let path = PathBuf::from(file_path);
                    if !path.exists() {
                        return json!({"content": [{"type": "text", "text": format!("Error: File does not exist: {}", file_path)}]});
                    }
                    let min_len = params.arguments.get("min_length").and_then(|v| v.as_u64()).unwrap_or(4) as usize;
                    match extract_strings(&path, min_len) {
                        Ok(strings) => {
                            let all_strings: Vec<String> = [strings.ascii_strings, strings.unicode_strings].concat();
                            json!({"content": [{"type": "text", "text": serde_json::to_string_pretty(&all_strings).unwrap_or_default()}]})
                        }
                        Err(e) => json!({"content": [{"type": "text", "text": format!("Error: {}", e)}]}),
                    }
                } else {
                    json!({"content": [{"type": "text", "text": "Error: Missing file_path parameter"}]})
                }
            }
            "hex_dump_file" => {
                if let Some(file_path) = params.arguments.get("file_path").and_then(|v| v.as_str()) {
                    let path = PathBuf::from(file_path);
                    if !path.exists() {
                        return json!({"content": [{"type": "text", "text": format!("Error: File does not exist: {}", file_path)}]});
                    }
                    let size = params.arguments.get("size").and_then(|v| v.as_u64()).unwrap_or(256) as usize;
                    let offset = params.arguments.get("offset").and_then(|v| v.as_u64()).unwrap_or(0);
                    let hex_options = HexDumpOptions {
                        offset,
                        length: Some(size),
                        bytes_per_line: 16,
                        max_lines: None,
                    };
                    match generate_hex_dump(&path, hex_options) {
                        Ok(hex_dump) => {
                            let formatted = format_hex_dump_text(&hex_dump);
                            json!({"content": [{"type": "text", "text": formatted}]})
                        }
                        Err(e) => json!({"content": [{"type": "text", "text": format!("Error: {}", e)}]}),
                    }
                } else {
                    json!({"content": [{"type": "text", "text": "Error: Missing file_path parameter"}]})
                }
            }
            "analyze_binary_file" => {
                if let Some(file_path) = params.arguments.get("file_path").and_then(|v| v.as_str()) {
                    let path = PathBuf::from(file_path);
                    if !path.exists() {
                        return json!({"content": [{"type": "text", "text": format!("Error: File does not exist: {}", file_path)}]});
                    }
                    match parse_binary(&path) {
                        Ok(binary_info) => json!({"content": [{"type": "text", "text": serde_json::to_string_pretty(&binary_info).unwrap_or_default()}]}),
                        Err(e) => json!({"content": [{"type": "text", "text": format!("Error: {}", e)}]}),
                    }
                } else {
                    json!({"content": [{"type": "text", "text": "Error: Missing file_path parameter"}]})
                }
            }
            "get_file_metadata" => {
                if let Some(file_path) = params.arguments.get("file_path").and_then(|v| v.as_str()) {
                    let path = PathBuf::from(file_path);
                    if !path.exists() {
                        return json!({"content": [{"type": "text", "text": format!("Error: File does not exist: {}", file_path)}]});
                    }
                    match FileMetadata::new(&path) {
                        Ok(mut metadata) => {
                            if let Err(e) = metadata.extract_basic_info() {
                                return json!({"content": [{"type": "text", "text": format!("Error: {}", e)}]});
                            }
                            if let Err(e) = metadata.calculate_hashes().await {
                                return json!({"content": [{"type": "text", "text": format!("Error: {}", e)}]});
                            }
                            json!({"content": [{"type": "text", "text": serde_json::to_string_pretty(&metadata).unwrap_or_default()}]})
                        }
                        Err(e) => json!({"content": [{"type": "text", "text": format!("Error: {}", e)}]}),
                    }
                } else {
                    json!({"content": [{"type": "text", "text": "Error: Missing file_path parameter"}]})
                }
            }
            "verify_file_signatures" => {
                if let Some(file_path) = params.arguments.get("file_path").and_then(|v| v.as_str()) {
                    let path = PathBuf::from(file_path);
                    if !path.exists() {
                        return json!({"content": [{"type": "text", "text": format!("Error: File does not exist: {}", file_path)}]});
                    }
                    match verify_signature(&path) {
                        Ok(sig_info) => json!({"content": [{"type": "text", "text": format!("Signatures verified: {:?}", sig_info)}]}),
                        Err(e) => json!({"content": [{"type": "text", "text": format!("Error: {}", e)}]}),
                    }
                } else {
                    json!({"content": [{"type": "text", "text": "Error: Missing file_path parameter"}]})
                }
            }
            "analyze_function_symbols" => {
                if let Some(file_path) = params.arguments.get("file_path").and_then(|v| v.as_str()) {
                    let path = PathBuf::from(file_path);
                    if !path.exists() {
                        return json!({"content": [{"type": "text", "text": format!("Error: File does not exist: {}", file_path)}]});
                    }
                    match crate::function_analysis::analyze_symbols(&path) {
                        Ok(symbol_table) => json!({"content": [{"type": "text", "text": serde_json::to_string_pretty(&symbol_table).unwrap_or_default()}]}),
                        Err(e) => json!({"content": [{"type": "text", "text": format!("Error: {}", e)}]}),
                    }
                } else {
                    json!({"content": [{"type": "text", "text": "Error: Missing file_path parameter"}]})
                }
            }
            "analyze_control_flow_graph" => {
                if let Some(file_path) = params.arguments.get("file_path").and_then(|v| v.as_str()) {
                    let path = PathBuf::from(file_path);
                    if !path.exists() {
                        return json!({"content": [{"type": "text", "text": format!("Error: File does not exist: {}", file_path)}]});
                    }
                    match crate::function_analysis::analyze_symbols(&path) {
                        Ok(symbol_table) => {
                            match crate::control_flow::analyze_control_flow(&path, &symbol_table) {
                                Ok(cfg_analysis) => json!({"content": [{"type": "text", "text": serde_json::to_string_pretty(&cfg_analysis).unwrap_or_default()}]}),
                                Err(e) => json!({"content": [{"type": "text", "text": format!("Error: {}", e)}]}),
                            }
                        }
                        Err(e) => json!({"content": [{"type": "text", "text": format!("Error: Failed to analyze symbols: {}", e)}]}),
                    }
                } else {
                    json!({"content": [{"type": "text", "text": "Error: Missing file_path parameter"}]})
                }
            }
            "detect_vulnerabilities" => {
                if let Some(file_path) = params.arguments.get("file_path").and_then(|v| v.as_str()) {
                    let path = PathBuf::from(file_path);
                    if !path.exists() {
                        return json!({"content": [{"type": "text", "text": format!("Error: File does not exist: {}", file_path)}]});
                    }
                    match crate::function_analysis::analyze_symbols(&path) {
                        Ok(symbol_table) => {
                            match crate::control_flow::analyze_control_flow(&path, &symbol_table) {
                                Ok(cfg_analysis) => {
                                    match crate::vulnerability_detection::analyze_vulnerabilities(&path, &symbol_table, &cfg_analysis) {
                                        Ok(vuln_result) => json!({"content": [{"type": "text", "text": serde_json::to_string_pretty(&vuln_result).unwrap_or_default()}]}),
                                        Err(e) => json!({"content": [{"type": "text", "text": format!("Error: {}", e)}]}),
                                    }
                                }
                                Err(e) => json!({"content": [{"type": "text", "text": format!("Error: Failed to analyze control flow: {}", e)}]}),
                            }
                        }
                        Err(e) => json!({"content": [{"type": "text", "text": format!("Error: Failed to analyze symbols: {}", e)}]}),
                    }
                } else {
                    json!({"content": [{"type": "text", "text": "Error: Missing file_path parameter"}]})
                }
            }
            "analyze_code_quality" => {
                if let Some(file_path) = params.arguments.get("file_path").and_then(|v| v.as_str()) {
                    let path = PathBuf::from(file_path);
                    if !path.exists() {
                        return json!({"content": [{"type": "text", "text": format!("Error: File does not exist: {}", file_path)}]});
                    }
                    match crate::function_analysis::analyze_symbols(&path) {
                        Ok(symbol_table) => {
                            match crate::control_flow::analyze_control_flow(&path, &symbol_table) {
                                Ok(cfg_analysis) => {
                                    match crate::code_metrics::analyze_code_quality(&path, &symbol_table, &cfg_analysis) {
                                        Ok(quality_result) => json!({"content": [{"type": "text", "text": serde_json::to_string_pretty(&quality_result).unwrap_or_default()}]}),
                                        Err(e) => json!({"content": [{"type": "text", "text": format!("Error: {}", e)}]}),
                                    }
                                }
                                Err(e) => json!({"content": [{"type": "text", "text": format!("Error: Failed to analyze control flow: {}", e)}]}),
                            }
                        }
                        Err(e) => json!({"content": [{"type": "text", "text": format!("Error: Failed to analyze symbols: {}", e)}]}),
                    }
                } else {
                    json!({"content": [{"type": "text", "text": "Error: Missing file_path parameter"}]})
                }
            }
            "analyze_dependencies" => {
                if let Some(file_path) = params.arguments.get("file_path").and_then(|v| v.as_str()) {
                    let path = PathBuf::from(file_path);
                    if !path.exists() {
                        return json!({"content": [{"type": "text", "text": format!("Error: File does not exist: {}", file_path)}]});
                    }
                    match crate::function_analysis::analyze_symbols(&path) {
                        Ok(symbol_table) => {
                            let strings = extract_strings(&path, 4).ok();
                            match crate::dependency_analysis::analyze_dependencies(&path, &symbol_table, strings.as_ref()) {
                                Ok(dep_result) => json!({"content": [{"type": "text", "text": serde_json::to_string_pretty(&dep_result).unwrap_or_default()}]}),
                                Err(e) => json!({"content": [{"type": "text", "text": format!("Error: {}", e)}]}),
                            }
                        }
                        Err(e) => json!({"content": [{"type": "text", "text": format!("Error: Failed to analyze symbols: {}", e)}]}),
                    }
                } else {
                    json!({"content": [{"type": "text", "text": "Error: Missing file_path parameter"}]})
                }
            }
            "analyze_entropy_patterns" => {
                if let Some(file_path) = params.arguments.get("file_path").and_then(|v| v.as_str()) {
                    let path = PathBuf::from(file_path);
                    if !path.exists() {
                        return json!({"content": [{"type": "text", "text": format!("Error: File does not exist: {}", file_path)}]});
                    }
                    match crate::entropy_analysis::analyze_entropy(&path) {
                        Ok(entropy_result) => json!({"content": [{"type": "text", "text": serde_json::to_string_pretty(&entropy_result).unwrap_or_default()}]}),
                        Err(e) => json!({"content": [{"type": "text", "text": format!("Error: {}", e)}]}),
                    }
                } else {
                    json!({"content": [{"type": "text", "text": "Error: Missing file_path parameter"}]})
                }
            }
            "disassemble_code" => {
                if let Some(file_path) = params.arguments.get("file_path").and_then(|v| v.as_str()) {
                    let path = PathBuf::from(file_path);
                    if !path.exists() {
                        return json!({"content": [{"type": "text", "text": format!("Error: File does not exist: {}", file_path)}]});
                    }
                    match crate::function_analysis::analyze_symbols(&path) {
                        Ok(symbol_table) => {
                            match crate::disassembly::disassemble_binary(&path, &symbol_table) {
                                Ok(disassembly_result) => json!({"content": [{"type": "text", "text": serde_json::to_string_pretty(&disassembly_result).unwrap_or_default()}]}),
                                Err(e) => json!({"content": [{"type": "text", "text": format!("Error: {}", e)}]}),
                            }
                        }
                        Err(e) => json!({"content": [{"type": "text", "text": format!("Error: Failed to analyze symbols: {}", e)}]}),
                    }
                } else {
                    json!({"content": [{"type": "text", "text": "Error: Missing file_path parameter"}]})
                }
            }
            "detect_threats" => {
                if let Some(file_path) = params.arguments.get("file_path").and_then(|v| v.as_str()) {
                    let path = PathBuf::from(file_path);
                    if !path.exists() {
                        return json!({"content": [{"type": "text", "text": format!("Error: File does not exist: {}", file_path)}]});
                    }
                    match crate::threat_detection::analyze_threats(&path) {
                        Ok(threat_result) => json!({"content": [{"type": "text", "text": serde_json::to_string_pretty(&threat_result).unwrap_or_default()}]}),
                        Err(e) => json!({"content": [{"type": "text", "text": format!("Error: {}", e)}]}),
                    }
                } else {
                    json!({"content": [{"type": "text", "text": "Error: Missing file_path parameter"}]})
                }
            }
            "analyze_behavioral_patterns" => {
                if let Some(file_path) = params.arguments.get("file_path").and_then(|v| v.as_str()) {
                    let path = PathBuf::from(file_path);
                    if !path.exists() {
                        return json!({"content": [{"type": "text", "text": format!("Error: File does not exist: {}", file_path)}]});
                    }
                    // Extract strings
                    let strings = crate::strings::extract_strings(&path, 4).ok();
                    // Get symbols
                    let symbols = crate::function_analysis::analyze_symbols(&path).ok();
                    // Get disassembly if possible
                    let disassembly = if let Some(ref syms) = symbols {
                        crate::disassembly::disassemble_binary(&path, syms).ok()
                    } else {
                        None
                    };
                    // Analyze behavior
                    match crate::behavioral_analysis::analyze_behavior(&path, strings.as_ref(), symbols.as_ref(), disassembly.as_ref()) {
                        Ok(behavioral_result) => json!({"content": [{"type": "text", "text": serde_json::to_string_pretty(&behavioral_result).unwrap_or_default()}]}),
                        Err(e) => json!({"content": [{"type": "text", "text": format!("Error: {}", e)}]}),
                    }
                } else {
                    json!({"content": [{"type": "text", "text": "Error: Missing file_path parameter"}]})
                }
            }
            _ => json!({"content": [{"type": "text", "text": format!("Error: Unknown tool: {}", params.name)}]}),
        }
    }
}

// HTTP handlers
async fn handle_mcp_http_request(
    State(state): State<McpServerState>,
    AxumJson(request): AxumJson<JsonRpcRequest>,
) -> Result<AxumJson<JsonRpcResponse>, StatusCode> {
    let server = McpTransportServer {
        handler: state.handler,
    };
    let response = server.handle_jsonrpc_request(request).await;
    Ok(AxumJson(response))
}

async fn handle_initialize(
    State(state): State<McpServerState>,
) -> Result<AxumJson<Value>, StatusCode> {
    use rmcp::ServerHandler;
    let info = state.handler.get_info();
    Ok(AxumJson(json!({
        "protocolVersion": "2024-11-05",
        "serverInfo": info.server_info,
        "capabilities": info.capabilities
    })))
}

async fn handle_tools_list(
    State(_state): State<McpServerState>,
) -> Result<AxumJson<Value>, StatusCode> {
    Ok(AxumJson(json!({
        "tools": [
            {
                "name": "calculate_file_hashes",
                "description": "Calculate cryptographic hashes (MD5, SHA256, SHA512, BLAKE3) for a file"
            },
            {
                "name": "extract_file_strings", 
                "description": "Extract ASCII and Unicode strings from a file"
            },
            {
                "name": "hex_dump_file",
                "description": "Generate a hex dump of a file or part of a file"
            },
            {
                "name": "analyze_binary_file",
                "description": "Analyze binary file format (PE, ELF, Mach-O) and extract metadata"
            },
            {
                "name": "get_file_metadata",
                "description": "Extract file system metadata including timestamps, permissions, and file type"
            },
            {
                "name": "verify_file_signatures",
                "description": "Verify digital signatures on a file"
            },
            {
                "name": "analyze_function_symbols",
                "description": "Analyze function symbols and cross-references in a binary file"
            },
            {
                "name": "analyze_control_flow_graph",
                "description": "Analyze control flow graphs, basic blocks, and complexity metrics in a binary file"
            },
            {
                "name": "detect_vulnerabilities",
                "description": "Detect security vulnerabilities using static analysis patterns and rules"
            },
            {
                "name": "analyze_code_quality",
                "description": "Analyze code quality metrics including complexity, maintainability, and technical debt"
            },
            {
                "name": "analyze_dependencies",
                "description": "Analyze library dependencies, detect vulnerable libraries, and check license compliance"
            },
            {
                "name": "analyze_entropy_patterns",
                "description": "Analyze entropy patterns to detect packing, encryption, and obfuscation techniques"
            },
            {
                "name": "disassemble_code",
                "description": "Disassemble binary code with multi-architecture support and advanced instruction analysis"
            },
            {
                "name": "detect_threats",
                "description": "Detect threats and malware using YARA-X rules with comprehensive pattern matching"
            },
            {
                "name": "analyze_behavioral_patterns",
                "description": "Analyze behavioral patterns including anti-analysis, persistence, and evasion techniques"
            }
        ]
    })))
}

async fn handle_tools_call(
    State(state): State<McpServerState>,
    AxumJson(params): AxumJson<ToolCallParams>,
) -> Result<AxumJson<Value>, StatusCode> {
    let server = McpTransportServer {
        handler: state.handler,
    };
    let result = server.handle_tool_call(params).await;
    Ok(AxumJson(result))
}

// SSE handlers
async fn handle_sse_connection(
    Query(query): Query<SseQuery>,
    State(state): State<McpServerState>,
) -> Sse<impl Stream<Item = Result<axum::response::sse::Event, std::convert::Infallible>>> {
    let client_id = query.client_id.unwrap_or_else(|| Uuid::new_v4().to_string());
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    
    // Store the client
    {
        let mut clients = state.sse_clients.lock().unwrap();
        clients.insert(client_id.clone(), tx.clone());
    }
    
    // Send initial connection event
    let _ = tx.send(SseEvent {
        id: Some("init".to_string()),
        event: Some("connected".to_string()),
        data: json!({
            "client_id": client_id,
            "message": "Connected to MCP File Scanner server"
        }).to_string(),
    });
    
    let stream = UnboundedReceiverStream::new(rx).map(|event| {
        let mut sse_event = axum::response::sse::Event::default().data(event.data);
        if let Some(id) = event.id {
            sse_event = sse_event.id(id);
        }
        if let Some(event_type) = event.event {
            sse_event = sse_event.event(event_type);
        }
        Ok(sse_event)
    });
    
    Sse::new(stream).keep_alive(
        axum::response::sse::KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("keep-alive-text"),
    )
}

async fn handle_mcp_sse_request(
    State(state): State<McpServerState>,
    AxumJson(request): AxumJson<JsonRpcRequest>,
) -> Result<AxumJson<JsonRpcResponse>, StatusCode> {
    let server = McpTransportServer {
        handler: state.handler,
    };
    let response = server.handle_jsonrpc_request(request).await;
    
    // Broadcast response to SSE clients
    let event = SseEvent {
        id: Some(Uuid::new_v4().to_string()),
        event: Some("mcp_response".to_string()),
        data: serde_json::to_string(&response).unwrap_or_default(),
    };
    
    let clients = state.sse_clients.lock().unwrap();
    for (_, sender) in clients.iter() {
        let _ = sender.send(event.clone());
    }
    
    Ok(AxumJson(response))
}

async fn health_check() -> AxumJson<serde_json::Value> {
    AxumJson(serde_json::json!({
        "status": "healthy",
        "service": "file-scanner-mcp",
        "version": "0.1.0",
        "transports": ["stdio", "http", "sse"]
    }))
}

async fn cors_middleware(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let mut response = next.run(request).await;
    
    let headers = response.headers_mut();
    headers.insert("Access-Control-Allow-Origin", "*".parse().unwrap());
    headers.insert("Access-Control-Allow-Methods", "GET, POST, OPTIONS".parse().unwrap());
    headers.insert("Access-Control-Allow-Headers", "Content-Type, Authorization, Cache-Control".parse().unwrap());
    headers.insert("Cache-Control", "no-cache".parse().unwrap());
    
    response
}