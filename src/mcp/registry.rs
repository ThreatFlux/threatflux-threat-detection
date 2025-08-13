use async_trait::async_trait;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;

use crate::mcp::error::McpResult;

/// Tool metadata for registration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolMetadata {
    pub name: String,
    pub description: String,
    pub input_schema: Value,
}

/// Trait for MCP tools
#[async_trait]
pub trait McpTool: Send + Sync {
    /// Get tool metadata
    fn metadata(&self) -> ToolMetadata;

    /// Execute the tool with given arguments
    async fn execute(&self, arguments: HashMap<String, Value>) -> McpResult<Value>;
}

/// Registry for MCP tools
#[derive(Clone)]
pub struct ToolRegistry {
    tools: Arc<HashMap<String, Arc<dyn McpTool>>>,
}

impl ToolRegistry {
    pub fn new() -> Self {
        Self {
            tools: Arc::new(HashMap::new()),
        }
    }

    /// Create a builder for registering tools
    pub fn builder() -> ToolRegistryBuilder {
        ToolRegistryBuilder::new()
    }

    /// Get a tool by name
    pub fn get(&self, name: &str) -> Option<Arc<dyn McpTool>> {
        self.tools.get(name).cloned()
    }

    /// List all registered tools
    pub fn list(&self) -> Vec<ToolMetadata> {
        self.tools.values().map(|tool| tool.metadata()).collect()
    }

    /// Check if a tool is registered
    pub fn has(&self, name: &str) -> bool {
        self.tools.contains_key(name)
    }
}

/// Builder for ToolRegistry
pub struct ToolRegistryBuilder {
    tools: HashMap<String, Arc<dyn McpTool>>,
}

impl ToolRegistryBuilder {
    pub fn new() -> Self {
        Self {
            tools: HashMap::new(),
        }
    }

    /// Register a tool
    pub fn register<T: McpTool + 'static>(mut self, tool: T) -> Self {
        let metadata = tool.metadata();
        self.tools.insert(metadata.name.clone(), Arc::new(tool));
        self
    }

    /// Build the registry
    pub fn build(self) -> ToolRegistry {
        ToolRegistry {
            tools: Arc::new(self.tools),
        }
    }
}

/// Helper to create input schema from a type
pub fn create_input_schema<T: JsonSchema>() -> Value {
    let schema = schemars::schema_for!(T);
    serde_json::to_value(schema).unwrap_or(Value::Null)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // Mock tool for testing
    struct MockTool {
        name: String,
        description: String,
    }

    #[async_trait]
    impl McpTool for MockTool {
        fn metadata(&self) -> ToolMetadata {
            ToolMetadata {
                name: self.name.clone(),
                description: self.description.clone(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "test": {"type": "string"}
                    }
                }),
            }
        }

        async fn execute(&self, _arguments: HashMap<String, Value>) -> McpResult<Value> {
            Ok(json!({"result": "test"}))
        }
    }

    #[test]
    fn test_tool_registry() {
        let registry = ToolRegistry::builder()
            .register(MockTool {
                name: "test_tool".to_string(),
                description: "Test tool".to_string(),
            })
            .build();

        assert!(registry.has("test_tool"));
        assert!(!registry.has("nonexistent"));

        let tools = registry.list();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].name, "test_tool");
    }

    #[tokio::test]
    async fn test_tool_execution() {
        let tool = MockTool {
            name: "test".to_string(),
            description: "Test".to_string(),
        };

        let result = tool.execute(HashMap::new()).await.unwrap();
        assert_eq!(result["result"], "test");
    }
}
