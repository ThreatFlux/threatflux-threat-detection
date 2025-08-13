use anyhow::Result;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use crate::mcp::handler::McpHandler;
use crate::mcp::transport::common::{handle_jsonrpc_request, JsonRpcError, JsonRpcRequest, JsonRpcResponse};

pub struct StdioTransport {
    handler: McpHandler,
}

impl StdioTransport {
    pub fn new(handler: McpHandler) -> Self {
        Self { handler }
    }

    pub async fn run(self) -> Result<()> {
        use rmcp::ServerHandler;

        let info = self.handler.get_info();
        eprintln!("MCP Server starting: {}", info.server_info.name);
        eprintln!("Version: {}", info.server_info.version);
        eprintln!("Protocol: {}", info.protocol_version);
        eprintln!("Use with: npx @modelcontextprotocol/inspector ./target/release/file-scanner mcp-stdio");

        let stdin = tokio::io::stdin();
        let mut stdout = tokio::io::stdout();
        let mut reader = BufReader::new(stdin);
        let mut line = String::new();

        loop {
            line.clear();
            match reader.read_line(&mut line).await {
                Ok(0) => break, // EOF
                Ok(_) => {
                    let trimmed = line.trim();
                    if trimmed.is_empty() {
                        continue;
                    }

                    let response = match serde_json::from_str::<JsonRpcRequest>(trimmed) {
                        Ok(request) => handle_jsonrpc_request(&self.handler, request).await,
                        Err(e) => JsonRpcResponse {
                            jsonrpc: "2.0".to_string(),
                            id: None,
                            result: None,
                            error: Some(JsonRpcError {
                                code: -32700,
                                message: format!("Parse error: {}", e),
                                data: None,
                            }),
                        },
                    };

                    let response_str = serde_json::to_string(&response)?;
                    stdout.write_all(response_str.as_bytes()).await?;
                    stdout.write_all(b"\n").await?;
                    stdout.flush().await?;
                }
                Err(e) => {
                    eprintln!("Read error: {}", e);
                    break;
                }
            }
        }

        Ok(())
    }
}