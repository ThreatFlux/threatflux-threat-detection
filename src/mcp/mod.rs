// MCP module - Model Context Protocol implementation
pub mod error;
pub mod handler;
pub mod registry;
pub mod tools;
pub mod transport;

pub use error::{McpError, McpResult};
pub use handler::McpHandler;
pub use registry::{McpTool, ToolMetadata, ToolRegistry};