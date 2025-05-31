use anyhow::Result;
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{Json as AxumJson, Sse},
    routing::{get, post},
    Router,
};
use chrono::Utc;
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::net::TcpListener;
use tokio_stream::{wrappers::UnboundedReceiverStream, Stream};
use tower::ServiceBuilder;
use uuid::Uuid;

use crate::cache::{AnalysisCache, CacheEntry, CacheSearchQuery};
use crate::mcp_server::FileScannerMcp;
use crate::string_tracker::{StringFilter, StringTracker};

#[derive(Clone)]
pub struct McpServerState {
    handler: FileScannerMcp,
    sse_clients: Arc<Mutex<HashMap<String, tokio::sync::mpsc::UnboundedSender<SseEvent>>>>,
    cache: Arc<AnalysisCache>,
    string_tracker: Arc<StringTracker>,
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
    cache: Arc<AnalysisCache>,
    string_tracker: Arc<StringTracker>,
}

impl McpTransportServer {
    pub fn new() -> Self {
        let cache_dir = std::env::temp_dir().join("file-scanner-cache");
        let cache = Arc::new(AnalysisCache::new(cache_dir).expect("Failed to create cache"));
        let string_tracker = Arc::new(StringTracker::new());

        Self {
            handler: FileScannerMcp,
            cache,
            string_tracker,
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
        eprintln!(
            "Use with: npx @modelcontextprotocol/inspector ./target/release/file-scanner mcp-stdio"
        );

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
            cache: self.cache.clone(),
            string_tracker: self.string_tracker.clone(),
        };

        let app = Router::new()
            .route("/mcp", post(handle_mcp_http_request))
            .route("/health", get(health_check))
            .route("/initialize", post(handle_initialize))
            .route("/tools/list", post(handle_tools_list))
            .route("/tools/call", post(handle_tools_call))
            .route("/cache/list", get(handle_cache_list))
            .route("/cache/search", post(handle_cache_search))
            .route("/cache/stats", get(handle_cache_stats))
            .route("/cache/clear", post(handle_cache_clear))
            .route("/strings/stats", get(handle_strings_stats))
            .route("/strings/search", post(handle_strings_search))
            .route("/strings/details", post(handle_string_details))
            .route("/strings/related", post(handle_strings_related))
            .route("/strings/filter", post(handle_strings_filter))
            .with_state(state)
            .layer(ServiceBuilder::new().layer(axum::middleware::from_fn(cors_middleware)));

        let listener = TcpListener::bind(format!("0.0.0.0:{}", port)).await?;
        println!("MCP HTTP server listening on http://localhost:{}", port);
        println!("Endpoints:");
        println!("  - POST /mcp - MCP JSON-RPC endpoint");
        println!("  - GET /health - Health check");
        println!("  - POST /initialize - Initialize MCP session");
        println!("  - POST /tools/list - List available tools");
        println!("  - POST /tools/call - Call a tool");
        println!("  - GET /cache/list - List all cache entries");
        println!("  - POST /cache/search - Search cache with query");
        println!("  - GET /cache/stats - Get cache statistics");
        println!("  - POST /cache/clear - Clear all cache entries");
        println!("  - GET /strings/stats - Get string statistics");
        println!("  - POST /strings/search - Search for strings");
        println!("  - POST /strings/details - Get string details");
        println!("  - POST /strings/related - Find related strings");
        println!("  - POST /strings/filter - Filter strings with advanced criteria");
        println!();
        println!("Test with MCP Inspector:");
        println!(
            "  npx @modelcontextprotocol/inspector http://localhost:{}/mcp",
            port
        );

        axum::serve(listener, app).await?;
        Ok(())
    }

    /// Run MCP server with SSE transport
    pub async fn run_sse(&self, port: u16) -> Result<()> {
        let state = McpServerState {
            handler: self.handler.clone(),
            sse_clients: Arc::new(Mutex::new(HashMap::new())),
            cache: self.cache.clone(),
            string_tracker: self.string_tracker.clone(),
        };

        let app = Router::new()
            .route("/sse", get(handle_sse_connection))
            .route("/mcp", post(handle_mcp_sse_request))
            .route("/health", get(health_check))
            .with_state(state)
            .layer(ServiceBuilder::new().layer(axum::middleware::from_fn(cors_middleware)));

        let listener = TcpListener::bind(format!("0.0.0.0:{}", port)).await?;
        println!("MCP SSE server listening on http://localhost:{}", port);
        println!("Endpoints:");
        println!("  - GET /sse - SSE connection endpoint");
        println!("  - POST /mcp - MCP JSON-RPC over SSE");
        println!("  - GET /health - Health check");
        println!();
        println!("Test with MCP Inspector:");
        println!(
            "  npx @modelcontextprotocol/inspector http://localhost:{}/sse",
            port
        );

        axum::serve(listener, app).await?;
        Ok(())
    }

    pub async fn handle_jsonrpc_request(&self, request: JsonRpcRequest) -> JsonRpcResponse {
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
            "tools/list" => JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                id: request.id,
                result: Some(json!({
                    "tools": [
                        {
                            "name": "analyze_file",
                            "description": "Comprehensive file analysis tool - use flags to control which analyses to perform",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "file_path": {
                                        "type": "string",
                                        "description": "Path to the file to analyze"
                                    },
                                    "metadata": {
                                        "type": "boolean",
                                        "description": "Include file metadata (size, timestamps, permissions)"
                                    },
                                    "hashes": {
                                        "type": "boolean",
                                        "description": "Include cryptographic hashes (MD5, SHA256, SHA512, BLAKE3)"
                                    },
                                    "strings": {
                                        "type": "boolean",
                                        "description": "Extract strings from the file"
                                    },
                                    "min_string_length": {
                                        "type": "integer",
                                        "description": "Minimum string length (default: 4)"
                                    },
                                    "hex_dump": {
                                        "type": "boolean",
                                        "description": "Generate hex dump"
                                    },
                                    "hex_dump_size": {
                                        "type": "integer",
                                        "description": "Hex dump size in bytes (default: 256)"
                                    },
                                    "hex_dump_offset": {
                                        "type": "integer",
                                        "description": "Hex dump offset from start"
                                    },
                                    "binary_info": {
                                        "type": "boolean",
                                        "description": "Analyze binary format (PE/ELF/Mach-O)"
                                    },
                                    "signatures": {
                                        "type": "boolean",
                                        "description": "Verify digital signatures"
                                    },
                                    "symbols": {
                                        "type": "boolean",
                                        "description": "Analyze function symbols"
                                    },
                                    "control_flow": {
                                        "type": "boolean",
                                        "description": "Analyze control flow"
                                    },
                                    "vulnerabilities": {
                                        "type": "boolean",
                                        "description": "Detect vulnerabilities"
                                    },
                                    "code_quality": {
                                        "type": "boolean",
                                        "description": "Analyze code quality metrics"
                                    },
                                    "dependencies": {
                                        "type": "boolean",
                                        "description": "Analyze dependencies"
                                    },
                                    "entropy": {
                                        "type": "boolean",
                                        "description": "Analyze entropy patterns"
                                    },
                                    "disassembly": {
                                        "type": "boolean",
                                        "description": "Disassemble code"
                                    },
                                    "threats": {
                                        "type": "boolean",
                                        "description": "Detect threats and malware"
                                    },
                                    "behavioral": {
                                        "type": "boolean",
                                        "description": "Analyze behavioral patterns"
                                    },
                                    "yara_indicators": {
                                        "type": "boolean",
                                        "description": "Extract YARA rule indicators"
                                    }
                                },
                                "required": ["file_path"]
                            }
                        },
                        {
                            "name": "llm_analyze_file",
                            "description": "LLM-optimized file analysis for YARA rule generation - returns focused, token-limited output",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "file_path": {
                                        "type": "string",
                                        "description": "Path to the file to analyze"
                                    },
                                    "token_limit": {
                                        "type": "integer",
                                        "description": "Token limit for the response (default: 25000)"
                                    },
                                    "min_string_length": {
                                        "type": "integer",
                                        "description": "Minimum string length to extract (default: 6)"
                                    },
                                    "max_strings": {
                                        "type": "integer",
                                        "description": "Maximum number of strings to return (default: 50)"
                                    },
                                    "max_imports": {
                                        "type": "integer",
                                        "description": "Maximum number of imports to return (default: 30)"
                                    },
                                    "max_opcodes": {
                                        "type": "integer",
                                        "description": "Maximum number of opcodes to return (default: 10)"
                                    },
                                    "hex_pattern_size": {
                                        "type": "integer",
                                        "description": "Size of hex patterns to extract (default: 32)"
                                    },
                                    "suggest_yara_rule": {
                                        "type": "boolean",
                                        "description": "Generate YARA rule suggestion (default: true)"
                                    }
                                },
                                "required": ["file_path"]
                            }
                        }
                    ]
                })),
                error: None,
            },
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
        use crate::mcp_server::FileAnalysisRequest;
        use rmcp::handler::server::wrapper::Json;

        let start_time = Instant::now();

        match params.name.as_str() {
            "analyze_file" => {
                // Convert the arguments to FileAnalysisRequest
                match serde_json::from_value::<FileAnalysisRequest>(serde_json::json!(
                    params.arguments
                )) {
                    Ok(request) => {
                        // Call the unified analyze_file method
                        match self.handler.analyze_file(request).await {
                            Ok(Json(result)) => {
                                // Track strings if extracted
                                if let (Some(strings), Some(file_path)) = (
                                    &result.strings,
                                    params.arguments.get("file_path").and_then(|v| v.as_str()),
                                ) {
                                    if let Ok(hashes) = crate::hash::calculate_all_hashes(
                                        &std::path::PathBuf::from(file_path),
                                    )
                                    .await
                                    {
                                        let _ = self.string_tracker.track_strings_from_results(
                                            strings,
                                            file_path,
                                            &hashes.sha256,
                                            "analyze_file",
                                        );
                                    }
                                }

                                // Cache the result
                                if let Some(file_path) =
                                    params.arguments.get("file_path").and_then(|v| v.as_str())
                                {
                                    if let Ok(metadata) = std::fs::metadata(file_path) {
                                        if let Ok(hashes) = crate::hash::calculate_all_hashes(
                                            &std::path::PathBuf::from(file_path),
                                        )
                                        .await
                                        {
                                            let entry = CacheEntry {
                                                file_path: file_path.to_string(),
                                                file_hash: hashes.sha256,
                                                tool_name: "analyze_file".to_string(),
                                                tool_args: params.arguments.clone(),
                                                result: serde_json::to_value(&result)
                                                    .unwrap_or_default(),
                                                timestamp: Utc::now(),
                                                file_size: metadata.len(),
                                                execution_time_ms: start_time.elapsed().as_millis()
                                                    as u64,
                                            };
                                            let _ = self.cache.add_entry(entry);
                                        }
                                    }
                                }

                                json!({
                                    "content": [{
                                        "type": "text",
                                        "text": serde_json::to_string_pretty(&result).unwrap_or_default()
                                    }]
                                })
                            }
                            Err(e) => {
                                json!({
                                    "content": [{
                                        "type": "text",
                                        "text": format!("Error: {}", e)
                                    }]
                                })
                            }
                        }
                    }
                    Err(e) => {
                        json!({
                            "content": [{
                                "type": "text",
                                "text": format!("Error parsing request: {}", e)
                            }]
                        })
                    }
                }
            }
            "llm_analyze_file" => {
                // Convert the arguments to LlmFileAnalysisRequest
                match serde_json::from_value::<crate::mcp_server::LlmFileAnalysisRequest>(
                    serde_json::json!(params.arguments),
                ) {
                    Ok(request) => {
                        // Call the llm_analyze_file method
                        match self.handler.llm_analyze_file(request).await {
                            Ok(Json(result)) => {
                                json!({
                                    "content": [{
                                        "type": "text",
                                        "text": serde_json::to_string_pretty(&result).unwrap_or_default()
                                    }]
                                })
                            }
                            Err(e) => {
                                json!({
                                    "content": [{
                                        "type": "text",
                                        "text": format!("Error: {}", e)
                                    }]
                                })
                            }
                        }
                    }
                    Err(e) => {
                        json!({
                            "content": [{
                                "type": "text",
                                "text": format!("Error parsing request: {}", e)
                            }]
                        })
                    }
                }
            }
            _ => {
                json!({"content": [{"type": "text", "text": format!("Error: Unknown tool: {}", params.name)}]})
            }
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
        cache: state.cache.clone(),
        string_tracker: state.string_tracker.clone(),
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
                "name": "analyze_file",
                "description": "Comprehensive file analysis tool - use flags to control which analyses to perform"
            },
            {
                "name": "llm_analyze_file",
                "description": "LLM-optimized file analysis for YARA rule generation - returns focused, token-limited output"
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
        cache: state.cache.clone(),
        string_tracker: state.string_tracker.clone(),
    };
    let result = server.handle_tool_call(params).await;
    Ok(AxumJson(result))
}

// SSE handlers
async fn handle_sse_connection(
    Query(query): Query<SseQuery>,
    State(state): State<McpServerState>,
) -> Sse<impl Stream<Item = Result<axum::response::sse::Event, std::convert::Infallible>>> {
    let client_id = query
        .client_id
        .unwrap_or_else(|| Uuid::new_v4().to_string());
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
        })
        .to_string(),
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
        cache: state.cache.clone(),
        string_tracker: state.string_tracker.clone(),
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
    headers.insert(
        "Access-Control-Allow-Methods",
        "GET, POST, OPTIONS".parse().unwrap(),
    );
    headers.insert(
        "Access-Control-Allow-Headers",
        "Content-Type, Authorization, Cache-Control"
            .parse()
            .unwrap(),
    );
    headers.insert("Cache-Control", "no-cache".parse().unwrap());

    response
}

// Cache management handlers
async fn handle_cache_list(
    State(state): State<McpServerState>,
) -> Result<AxumJson<Value>, StatusCode> {
    let entries = state.cache.get_all_entries();
    Ok(AxumJson(json!({
        "entries": entries,
        "count": entries.len()
    })))
}

async fn handle_cache_search(
    State(state): State<McpServerState>,
    AxumJson(query): AxumJson<CacheSearchQuery>,
) -> Result<AxumJson<Value>, StatusCode> {
    let results = state.cache.search_entries(&query);
    Ok(AxumJson(json!({
        "results": results,
        "count": results.len()
    })))
}

async fn handle_cache_stats(
    State(state): State<McpServerState>,
) -> Result<AxumJson<Value>, StatusCode> {
    let stats = state.cache.get_statistics();
    let metadata = state.cache.get_metadata();
    Ok(AxumJson(json!({
        "statistics": stats,
        "metadata": metadata
    })))
}

async fn handle_cache_clear(
    State(state): State<McpServerState>,
) -> Result<AxumJson<Value>, StatusCode> {
    match state.cache.clear() {
        Ok(_) => Ok(AxumJson(json!({
            "status": "success",
            "message": "Cache cleared successfully"
        }))),
        Err(e) => Ok(AxumJson(json!({
            "status": "error",
            "message": format!("Failed to clear cache: {}", e)
        }))),
    }
}

// String tracker handlers
async fn handle_strings_stats(
    State(state): State<McpServerState>,
) -> Result<AxumJson<Value>, StatusCode> {
    let stats = state.string_tracker.get_statistics(None);
    Ok(AxumJson(json!(stats)))
}

async fn handle_strings_search(
    State(state): State<McpServerState>,
    AxumJson(params): AxumJson<HashMap<String, Value>>,
) -> Result<AxumJson<Value>, StatusCode> {
    let query = params.get("query").and_then(|v| v.as_str()).unwrap_or("");
    let limit = params.get("limit").and_then(|v| v.as_u64()).unwrap_or(100) as usize;

    let results = state.string_tracker.search_strings(query, limit);
    Ok(AxumJson(json!({
        "results": results,
        "count": results.len()
    })))
}

async fn handle_string_details(
    State(state): State<McpServerState>,
    AxumJson(params): AxumJson<HashMap<String, Value>>,
) -> Result<AxumJson<Value>, StatusCode> {
    let value = params.get("value").and_then(|v| v.as_str()).unwrap_or("");

    match state.string_tracker.get_string_details(value) {
        Some(details) => Ok(AxumJson(json!(details))),
        None => Ok(AxumJson(json!({
            "error": "String not found"
        }))),
    }
}

async fn handle_strings_related(
    State(state): State<McpServerState>,
    AxumJson(params): AxumJson<HashMap<String, Value>>,
) -> Result<AxumJson<Value>, StatusCode> {
    let value = params.get("value").and_then(|v| v.as_str()).unwrap_or("");
    let limit = params.get("limit").and_then(|v| v.as_u64()).unwrap_or(20) as usize;

    let related = state.string_tracker.get_related_strings(value, limit);
    Ok(AxumJson(json!({
        "related": related,
        "count": related.len()
    })))
}

async fn handle_strings_filter(
    State(state): State<McpServerState>,
    AxumJson(filter): AxumJson<StringFilter>,
) -> Result<AxumJson<Value>, StatusCode> {
    let stats = state.string_tracker.get_statistics(Some(&filter));
    Ok(AxumJson(json!(stats)))
}
