use anyhow::Result;
use file_scanner::npm_analysis::analyze_npm_package;
use std::path::Path;

#[tokio::main]
async fn main() -> Result<()> {
    let package_path = Path::new("test_npm_packages/package");
    
    println!("Analyzing Express npm package...\n");
    
    match analyze_npm_package(package_path) {
        Ok(analysis) => {
            let json = serde_json::to_string_pretty(&analysis)?;
            println!("{}", json);
        }
        Err(e) => {
            eprintln!("Error analyzing package: {}", e);
        }
    }
    
    Ok(())
}