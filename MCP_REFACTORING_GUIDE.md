# MCP Server Refactoring Guide

## Overview

This guide documents the refactoring of the MCP (Model Context Protocol) server components to create a cleaner, more modular architecture.

## Key Improvements

### 1. **Modular Structure**

**Before:**
- Single large `mcp_server.rs` file (2000+ lines)
- Mixed concerns (tool implementation, transport, registry)
- Duplicated code across tool handlers

**After:**
```
src/mcp/
├── mod.rs           # Module exports
├── error.rs         # Unified error handling
├── handler.rs       # Main MCP handler
├── registry.rs      # Tool registry system
├── tools/           # Individual tool implementations
│   ├── mod.rs
│   ├── analyze_file.rs
│   ├── llm_analyze.rs
│   ├── yara_scan.rs
│   ├── java_analyze.rs
│   ├── npm_analyze.rs
│   └── python_analyze.rs
└── transport/       # Transport implementations
    ├── mod.rs
    ├── common.rs    # Shared JSON-RPC handling
    ├── stdio.rs
    ├── http.rs
    └── sse.rs
```

### 2. **Tool Registry System**

**Before:**
```rust
// Hard-coded tool handling in handle_tool_call
match params.name.as_str() {
    "analyze_file" => { /* 100+ lines */ }
    "llm_analyze_file" => { /* 100+ lines */ }
    // ... more tools
}
```

**After:**
```rust
// Dynamic tool registry with trait-based tools
pub trait McpTool: Send + Sync {
    fn metadata(&self) -> ToolMetadata;
    async fn execute(&self, arguments: HashMap<String, Value>) -> McpResult<Value>;
}

// Automatic tool registration
let registry = ToolRegistry::builder()
    .register(AnalyzeFileTool::new(cache, tracker))
    .register(LlmAnalyzeTool::new())
    .build();

// Simple tool execution
let tool = registry.get(name)?;
tool.execute(arguments).await
```

### 3. **Unified Error Handling**

**Before:**
```rust
// Mixed error handling approaches
Err(format!("File does not exist: {}", path))
Err(e) => json!({"error": e.to_string()})
```

**After:**
```rust
// Typed error system with JSON-RPC compliance
pub enum McpError {
    ParseError { message: String },
    InvalidRequest { message: String },
    MethodNotFound { method: String },
    InvalidParams { message: String },
    InternalError { message: String },
}

// Automatic conversion to JSON-RPC errors
impl From<McpError> for JsonRpcError { ... }
```

### 4. **Separated Transport Logic**

**Before:**
- Transport logic mixed with business logic
- Duplicated JSON-RPC handling across transports
- Complex state management

**After:**
- Clean transport abstractions
- Shared JSON-RPC request handler
- Transport-specific concerns isolated

### 5. **Dependency Injection**

**Before:**
```rust
// Hard-coded dependencies in tool implementations
let cache = Arc::new(AnalysisCache::new(...));
let tracker = Arc::new(StringTracker::new());
```

**After:**
```rust
// Dependencies injected through constructors
pub struct AnalyzeFileTool {
    cache: Option<Arc<AnalysisCache>>,
    string_tracker: Option<Arc<StringTracker>>,
}

impl AnalyzeFileTool {
    pub fn new(
        cache: Option<Arc<AnalysisCache>>,
        string_tracker: Option<Arc<StringTracker>>,
    ) -> Self {
        Self { cache, string_tracker }
    }
}
```

## Migration Path

### Step 1: Create New Module Structure
1. Create `src/mcp/` directory
2. Move error types to `error.rs`
3. Extract tool trait to `registry.rs`
4. Create individual tool modules

### Step 2: Refactor Tools
1. Convert each tool to implement `McpTool` trait
2. Extract common logic to shared functions
3. Use dependency injection for cache/tracking

### Step 3: Update Transport Layer
1. Extract common JSON-RPC handling
2. Create transport-specific modules
3. Use the new handler for all transports

### Step 4: Integration
1. Update `main.rs` to use new structure
2. Add compatibility layer for existing code
3. Test all functionality

## Benefits

### 1. **Easier to Add New Tools**
```rust
// Just implement the trait and register
struct NewTool;

#[async_trait]
impl McpTool for NewTool {
    fn metadata(&self) -> ToolMetadata { ... }
    async fn execute(&self, args: HashMap<String, Value>) -> McpResult<Value> { ... }
}

// Register it
registry.register(NewTool);
```

### 2. **Better Testing**
- Each tool can be tested independently
- Mock dependencies easily
- Test transport logic separately

### 3. **Code Reuse**
- Common error handling
- Shared JSON-RPC logic
- Reusable tool patterns

### 4. **Maintainability**
- Clear separation of concerns
- Smaller, focused files
- Easy to understand flow

### 5. **Extensibility**
- Plugin-like architecture
- Easy to add new transports
- Simple to extend functionality

## Future Enhancements

### 1. **External Library Integration**
Once analysis modules are extracted to external crates:
```rust
// Replace internal imports
use file_scanner_core::{analyze_binary, calculate_hashes};
use file_scanner_strings::extract_strings;
use file_scanner_threats::analyze_threats;
```

### 2. **Dynamic Tool Loading**
```rust
// Load tools from plugins
registry.load_plugin("path/to/plugin.so")?;
```

### 3. **Tool Composition**
```rust
// Combine multiple tools
let composite = CompositeToolBuilder::new()
    .add_step(AnalyzeFileTool::new())
    .add_step(ThreatDetectionTool::new())
    .build();
```

### 4. **Middleware System**
```rust
// Add cross-cutting concerns
registry.with_middleware(CachingMiddleware::new())
        .with_middleware(LoggingMiddleware::new())
        .with_middleware(MetricsMiddleware::new());
```

## Conclusion

This refactoring significantly improves the maintainability, testability, and extensibility of the MCP server components while maintaining full backward compatibility. The modular structure makes it easy to understand, modify, and extend the system.