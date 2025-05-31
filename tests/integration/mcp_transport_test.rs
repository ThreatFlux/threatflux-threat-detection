use file_scanner::mcp_transport::{run_stdio_transport, run_http_transport, HttpTransportOptions};
use file_scanner::mcp_server::FileScannerMcpServer;
use rmcp::{Request, Response, JsonRpcRequest, JsonRpcResponse};
use serde_json::{json, Value};
use std::time::Duration;
use tokio::time::timeout;
use reqwest;

#[tokio::test]
async fn test_http_transport_server_start() {
    let server = FileScannerMcpServer;
    let port = 0; // Let OS assign a port
    
    let options = HttpTransportOptions {
        port,
        host: "127.0.0.1".to_string(),
    };
    
    // Start server in background
    let server_handle = tokio::spawn(async move {
        run_http_transport(server, options).await
    });
    
    // Give server time to start
    tokio::time::sleep(Duration::from_millis(100)).await;
    
    // Server should be running
    assert!(!server_handle.is_finished());
    
    // Clean up
    server_handle.abort();
}

#[tokio::test]
async fn test_http_transport_mcp_endpoint() {
    let server = FileScannerMcpServer;
    let port = 3456; // Use a specific port for testing
    
    let options = HttpTransportOptions {
        port,
        host: "127.0.0.1".to_string(),
    };
    
    // Start server in background
    let server_handle = tokio::spawn(async move {
        run_http_transport(server, options).await
    });
    
    // Give server time to start
    tokio::time::sleep(Duration::from_millis(200)).await;
    
    // Test the /mcp endpoint
    let client = reqwest::Client::new();
    
    // Send a tools/list request
    let request = json!({
        "jsonrpc": "2.0",
        "method": "tools/list",
        "params": {},
        "id": 1
    });
    
    let response = client
        .post(&format!("http://127.0.0.1:{}/mcp", port))
        .json(&request)
        .send()
        .await;
    
    assert!(response.is_ok());
    let response = response.unwrap();
    assert_eq!(response.status(), 200);
    
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["jsonrpc"], "2.0");
    assert_eq!(body["id"], 1);
    
    // Should have a result with tools array
    assert!(body["result"].is_object());
    assert!(body["result"]["tools"].is_array());
    
    let tools = body["result"]["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 2); // analyze_file and llm_analyze_file
    
    // Clean up
    server_handle.abort();
}

#[tokio::test]
async fn test_http_transport_health_endpoint() {
    let server = FileScannerMcpServer;
    let port = 3457;
    
    let options = HttpTransportOptions {
        port,
        host: "127.0.0.1".to_string(),
    };
    
    // Start server
    let server_handle = tokio::spawn(async move {
        run_http_transport(server, options).await
    });
    
    tokio::time::sleep(Duration::from_millis(200)).await;
    
    // Test health endpoint
    let client = reqwest::Client::new();
    let response = client
        .get(&format!("http://127.0.0.1:{}/health", port))
        .send()
        .await;
    
    assert!(response.is_ok());
    let response = response.unwrap();
    assert_eq!(response.status(), 200);
    
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["status"], "ok");
    assert!(body["mcp_version"].is_string());
    
    server_handle.abort();
}

#[tokio::test]
async fn test_http_transport_cache_endpoints() {
    let server = FileScannerMcpServer;
    let port = 3458;
    
    let options = HttpTransportOptions {
        port,
        host: "127.0.0.1".to_string(),
    };
    
    let server_handle = tokio::spawn(async move {
        run_http_transport(server, options).await
    });
    
    tokio::time::sleep(Duration::from_millis(200)).await;
    
    let client = reqwest::Client::new();
    
    // Test cache stats
    let response = client
        .get(&format!("http://127.0.0.1:{}/cache/stats", port))
        .send()
        .await
        .unwrap();
    
    assert_eq!(response.status(), 200);
    let stats: Value = response.json().await.unwrap();
    assert!(stats["total_entries"].is_number());
    assert!(stats["total_size_bytes"].is_number());
    
    // Test cache list
    let response = client
        .get(&format!("http://127.0.0.1:{}/cache/list", port))
        .send()
        .await
        .unwrap();
    
    assert_eq!(response.status(), 200);
    let entries: Value = response.json().await.unwrap();
    assert!(entries.is_array());
    
    // Test cache clear
    let response = client
        .post(&format!("http://127.0.0.1:{}/cache/clear", port))
        .send()
        .await
        .unwrap();
    
    assert_eq!(response.status(), 200);
    
    server_handle.abort();
}

#[tokio::test]
async fn test_http_transport_string_tracker_endpoints() {
    let server = FileScannerMcpServer;
    let port = 3459;
    
    let options = HttpTransportOptions {
        port,
        host: "127.0.0.1".to_string(),
    };
    
    let server_handle = tokio::spawn(async move {
        run_http_transport(server, options).await
    });
    
    tokio::time::sleep(Duration::from_millis(200)).await;
    
    let client = reqwest::Client::new();
    
    // Test string stats
    let response = client
        .get(&format!("http://127.0.0.1:{}/strings/stats", port))
        .send()
        .await
        .unwrap();
    
    assert_eq!(response.status(), 200);
    let stats: Value = response.json().await.unwrap();
    assert!(stats["total_strings"].is_number());
    assert!(stats["unique_strings"].is_number());
    
    // Test string search
    let search_request = json!({
        "query": "test",
        "limit": 10
    });
    
    let response = client
        .post(&format!("http://127.0.0.1:{}/strings/search", port))
        .json(&search_request)
        .send()
        .await
        .unwrap();
    
    assert_eq!(response.status(), 200);
    let results: Vec<Value> = response.json().await.unwrap();
    assert!(results.is_empty() || results[0]["value"].is_string());
    
    server_handle.abort();
}

#[tokio::test]
async fn test_http_transport_tool_call() {
    let server = FileScannerMcpServer;
    let port = 3460;
    
    let options = HttpTransportOptions {
        port,
        host: "127.0.0.1".to_string(),
    };
    
    let server_handle = tokio::spawn(async move {
        run_http_transport(server, options).await
    });
    
    tokio::time::sleep(Duration::from_millis(200)).await;
    
    // Create a test file
    let temp_dir = tempfile::TempDir::new().unwrap();
    let test_file = temp_dir.path().join("test.txt");
    std::fs::write(&test_file, b"Test content").unwrap();
    
    let client = reqwest::Client::new();
    
    // Call analyze_file tool
    let request = json!({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": "analyze_file",
            "arguments": {
                "file_path": test_file.to_str().unwrap(),
                "metadata": true,
                "hashes": true
            }
        },
        "id": 2
    });
    
    let response = client
        .post(&format!("http://127.0.0.1:{}/mcp", port))
        .json(&request)
        .send()
        .await
        .unwrap();
    
    assert_eq!(response.status(), 200);
    
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["jsonrpc"], "2.0");
    assert_eq!(body["id"], 2);
    
    // Should have result with content
    assert!(body["result"].is_object());
    assert!(body["result"]["content"].is_array());
    
    let content = &body["result"]["content"][0];
    assert_eq!(content["type"], "text");
    
    // Parse the actual file analysis result
    let text_content: Value = serde_json::from_str(content["text"].as_str().unwrap()).unwrap();
    assert_eq!(text_content["file_size"], 12);
    assert!(text_content["hashes"].is_object());
    
    server_handle.abort();
}

#[tokio::test]
async fn test_http_transport_invalid_json_rpc() {
    let server = FileScannerMcpServer;
    let port = 3461;
    
    let options = HttpTransportOptions {
        port,
        host: "127.0.0.1".to_string(),
    };
    
    let server_handle = tokio::spawn(async move {
        run_http_transport(server, options).await
    });
    
    tokio::time::sleep(Duration::from_millis(200)).await;
    
    let client = reqwest::Client::new();
    
    // Send invalid JSON-RPC (missing method)
    let request = json!({
        "jsonrpc": "2.0",
        "params": {},
        "id": 1
    });
    
    let response = client
        .post(&format!("http://127.0.0.1:{}/mcp", port))
        .json(&request)
        .send()
        .await
        .unwrap();
    
    assert_eq!(response.status(), 200); // Still 200, but with error in response
    
    let body: Value = response.json().await.unwrap();
    assert!(body["error"].is_object());
    assert_eq!(body["error"]["code"], -32600); // Invalid request
    
    server_handle.abort();
}

#[tokio::test]
async fn test_http_transport_concurrent_requests() {
    let server = FileScannerMcpServer;
    let port = 3462;
    
    let options = HttpTransportOptions {
        port,
        host: "127.0.0.1".to_string(),
    };
    
    let server_handle = tokio::spawn(async move {
        run_http_transport(server, options).await
    });
    
    tokio::time::sleep(Duration::from_millis(200)).await;
    
    let client = reqwest::Client::new();
    
    // Send multiple concurrent requests
    let mut handles = vec![];
    
    for i in 0..10 {
        let client = client.clone();
        let handle = tokio::spawn(async move {
            let request = json!({
                "jsonrpc": "2.0",
                "method": "tools/list",
                "params": {},
                "id": i
            });
            
            client
                .post(&format!("http://127.0.0.1:3462/mcp"))
                .json(&request)
                .send()
                .await
        });
        handles.push(handle);
    }
    
    // All requests should succeed
    for handle in handles {
        let result = handle.await.unwrap();
        assert!(result.is_ok());
        assert_eq!(result.unwrap().status(), 200);
    }
    
    server_handle.abort();
}