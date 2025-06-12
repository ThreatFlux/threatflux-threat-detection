#![allow(dead_code)]

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

mod archive_analysis;
mod behavioral_analysis;
mod binary_parser;
mod cache;
mod call_graph;
mod code_metrics;
mod control_flow;
mod dependency_analysis;
mod disassembly;
mod entropy_analysis;
mod function_analysis;
mod hash;
mod hexdump;
mod java_analysis;
mod mcp_server;
mod mcp_transport;
mod metadata;
mod npm_analysis;
mod npm_vuln_db;
mod ole_vba_analysis;
mod pdf_analysis;
mod python_analysis;
mod python_vuln_db;
mod rar_analysis;
pub mod repository_integrity;
mod script_analysis;
mod sevenz_analysis;
mod signature;
mod string_tracker;
mod strings;
pub mod taint_tracking;
mod tar_analysis;
mod threat_detection;
pub mod typosquatting_detection;
mod vulnerability_detection;

use hexdump::{extract_footer_hex, extract_header_hex, generate_hex_dump, HexDumpOptions};
use mcp_transport::McpTransportServer;
use metadata::FileMetadata;

#[derive(Parser, Debug)]
#[command(name = "file-scanner")]
#[command(about = "A native static file scanner that provides comprehensive file metadata", long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Option<Commands>,

    #[arg(help = "Path to the file to scan (used when not in MCP mode)")]
    file_path: Option<PathBuf>,

    #[arg(short, long, help = "Output format (json, yaml, pretty)")]
    format: Option<String>,

    #[arg(short, long, help = "Extract strings from file")]
    strings: bool,

    #[arg(long, help = "Minimum string length to extract")]
    min_string_len: Option<usize>,

    #[arg(short, long, help = "Verify digital signatures")]
    verify_signatures: bool,

    #[arg(long, help = "Include hex dump of file header/footer")]
    hex_dump: bool,

    #[arg(long, help = "Bytes to dump from start of file", default_value = "512")]
    hex_dump_size: usize,

    #[arg(long, help = "Hex dump offset (0 for header, negative for footer)")]
    hex_dump_offset: Option<i64>,
}

#[derive(Subcommand, Debug)]
#[allow(clippy::enum_variant_names)]
enum Commands {
    /// Run as MCP server with stdio transport
    McpStdio,
    /// Run as MCP server with HTTP transport
    McpHttp {
        #[arg(short, long, default_value = "3000")]
        port: u16,
    },
    /// Run as MCP server with SSE transport
    McpSse {
        #[arg(short, long, default_value = "3000")]
        port: u16,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Handle MCP server modes
    match args.command {
        Some(Commands::McpStdio) => {
            let server = McpTransportServer::new();
            return server.run_stdio().await;
        }
        Some(Commands::McpHttp { port }) => {
            let server = McpTransportServer::new();
            return server.run_http(port).await;
        }
        Some(Commands::McpSse { port }) => {
            let server = McpTransportServer::new();
            return server.run_sse(port).await;
        }
        None => {
            // Continue with regular file scanning
        }
    }

    // Regular file scanning mode
    let file_path = args
        .file_path
        .ok_or_else(|| anyhow::anyhow!("File path is required for scanning mode"))?;

    if !file_path.exists() {
        anyhow::bail!("File not found: {:?}", file_path);
    }

    let mut metadata = FileMetadata::new(&file_path)?;

    metadata.extract_basic_info()?;

    metadata.calculate_hashes().await?;

    if let Ok(binary_info) = binary_parser::parse_binary(&file_path) {
        metadata.binary_info = Some(binary_info);
    }

    if args.strings {
        let min_len = args.min_string_len.unwrap_or(4);
        metadata.extracted_strings = Some(strings::extract_strings(&file_path, min_len)?);
    }

    if args.verify_signatures {
        metadata.signature_info = signature::verify_signature(&file_path).ok();
    }

    if args.hex_dump {
        let hex_result = if let Some(offset) = args.hex_dump_offset {
            if offset < 0 {
                extract_footer_hex(&file_path, args.hex_dump_size)
            } else {
                let options = HexDumpOptions {
                    offset: offset as u64,
                    length: Some(args.hex_dump_size),
                    bytes_per_line: 16,
                    max_lines: None,
                };
                generate_hex_dump(&file_path, options)
            }
        } else {
            extract_header_hex(&file_path, args.hex_dump_size)
        };

        metadata.hex_dump = hex_result.ok();
    }

    match args.format.as_deref() {
        Some("json") => {
            println!("{}", serde_json::to_string(&metadata)?);
        }
        Some("yaml") => {
            println!("{}", serde_yaml::to_string(&metadata)?);
        }
        _ => {
            println!("{}", serde_json::to_string_pretty(&metadata)?);
        }
    }

    Ok(())
}
