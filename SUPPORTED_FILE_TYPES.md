# Supported File Types and Formats

The file-scanner supports a comprehensive range of file types and formats for analysis. Below is a complete list organized by category:

## Binary Executables

### Native Binaries
- **ELF (Executable and Linkable Format)**
  - Linux/Unix executables and shared libraries
  - Detected by magic bytes: `\x7FELF`
  - Architectures: x86, x86_64, ARM, ARM64
  
- **PE (Portable Executable)**
  - Windows executables (.exe) and libraries (.dll)
  - Detected by magic bytes: `MZ`
  - Includes DOS header and PE header parsing
  
- **Mach-O (Mach Object)**
  - macOS/iOS executables and libraries
  - Detected by magic bytes: `\xCA\xFE\xBA\xBE` or `\xFE\xED\xFA`
  - Universal binaries supported

### Java/Android Binaries
- **Java Archives**
  - `.jar` - Java Archive files
  - `.war` - Web Application Archive
  - `.ear` - Enterprise Application Archive
  - `.class` - Individual Java class files (magic: `\xCA\xFE\xBA\xBE`)
  
- **Android Packages**
  - `.apk` - Android Application Package
  - `.aar` - Android Archive
  - `.dex` - Dalvik Executable format

## Package Formats

### Language-Specific Packages
- **NPM/Node.js Packages**
  - npm packages (directories with package.json)
  - `.tgz` - NPM package archives
  - Security analysis for dependencies and scripts
  
- **Python Packages**
  - `.whl` - Python wheel packages
  - `.tar.gz` - Python source distributions
  - `.zip` - Python zip archives
  - Python source directories with setup.py/pyproject.toml
  
## Archive Formats

### Compressed Archives
- **ZIP Archives**
  - `.zip` - Standard ZIP files (magic: `PK\x03\x04`)
  - Password-protected ZIPs
  - Self-extracting archives
  
- **7-Zip Archives**
  - `.7z` - 7-Zip compressed archives
  
- **RAR Archives**
  - `.rar` - WinRAR archives
  
- **TAR Archives**
  - `.tar` - Uncompressed tape archives
  - `.tar.gz` / `.tgz` - Gzip compressed TAR (magic: `\x1F\x8B`)
  - `.tar.bz2` - Bzip2 compressed TAR (magic: `BZh`)
  - `.tar.xz` - XZ compressed TAR

## Document Formats

### PDF Documents
- `.pdf` - Portable Document Format (magic: `%PDF`)
- Analysis includes:
  - JavaScript detection
  - Embedded files
  - Form fields
  - Digital signatures
  - Encryption status

### Microsoft Office Formats
- **OLE2/Legacy Office**
  - `.doc` - Word documents
  - `.xls` - Excel spreadsheets
  - `.ppt` - PowerPoint presentations
  - `.msg` - Outlook messages
  - `.pst` - Outlook data files
  
- **Office Open XML (Modern)**
  - `.docx` - Word documents
  - `.xlsx` - Excel spreadsheets
  - `.pptx` - PowerPoint presentations
  
- **Other Microsoft Formats**
  - `.vsd` - Visio documents
  - `.one` - OneNote files
  
### VBA/Macro Analysis
- Documents containing VBA macros
- Excel files with macros (.xlsm)
- Word documents with macros (.docm)

## Script Files

### Shell Scripts
- `.sh` - Bash/Shell scripts (shebang: `#!/`)
- `.bash` - Bash scripts
- `.zsh` - Z shell scripts

### Windows Scripts
- `.bat` - Batch files
- `.cmd` - Command files
- `.ps1` - PowerShell scripts
- `.vbs` - VBScript files

### Programming Languages
- `.py` - Python scripts
- `.js` - JavaScript files
- `.rb` - Ruby scripts
- `.pl` - Perl scripts

## Image Formats
- `.png` - PNG images (magic: `\x89PNG`)
- `.jpg` / `.jpeg` - JPEG images (magic: `\xFF\xD8\xFF`)
- `.gif` - GIF images (magic: `GIF8`)

## Compression Formats (Standalone)
- `.gz` - Gzip compressed files (magic: `\x1F\x8B`)
- `.bz2` - Bzip2 compressed files (magic: `BZh`)
- `.xz` - XZ compressed files

## Generic File Analysis

The scanner can analyze ANY file type with basic capabilities:
- File metadata (size, timestamps, permissions)
- Cryptographic hashes (MD5, SHA256, SHA512, BLAKE3)
- String extraction (ASCII and Unicode)
- Hex dump generation
- Entropy analysis
- MIME type detection

## Special Analysis Features

### Digital Signatures
- Authenticode signatures (Windows)
- GPG signatures
- macOS code signatures
- JAR signing certificates

### Binary Analysis
- Compiler detection
- Import/Export table analysis
- Section analysis
- Symbol extraction
- Control flow analysis
- Disassembly support

### Security Analysis
- Vulnerability detection
- Malicious pattern detection
- Typosquatting detection (npm/Python packages)
- Supply chain risk assessment
- Obfuscation detection

## File Type Detection Methods

1. **Magic Bytes/Headers**
   - First few bytes of file checked against known signatures
   - Most reliable method for binary formats

2. **File Extension**
   - Secondary method, used when magic bytes unavailable
   - Case-insensitive matching

3. **Content Analysis**
   - For text files, analyzes content patterns
   - Detects script types by syntax

4. **MIME Type Detection**
   - Standard MIME type identification
   - Falls back to `application/octet-stream` for unknown types

## Limitations

- Maximum file size for full analysis: 100MB (configurable)
- String extraction limited to prevent memory exhaustion
- Some encrypted formats cannot be fully analyzed without passwords
- Archive bomb detection prevents infinite recursion

## Adding New File Types

The modular architecture allows easy addition of new file types:
1. Add detection logic to `metadata.rs` or specific analyzer
2. Create new analysis module if needed
3. Register in MCP server tools if applicable