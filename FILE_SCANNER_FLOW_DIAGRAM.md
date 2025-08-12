# File Scanner Execution Flow & Decision Tree

## Main Execution Flow

```mermaid
flowchart TD
    Start([User Invokes file-scanner]) --> ParseArgs{Parse CLI Arguments}
    
    ParseArgs --> |MCP Mode| MCPMode{Which Transport?}
    ParseArgs --> |Standalone| StandaloneMode[Direct File Analysis]
    
    MCPMode --> |STDIO| StdioServer[Run STDIO Server]
    MCPMode --> |HTTP| HttpServer[Run HTTP Server<br/>Port: specified]
    MCPMode --> |SSE| SseServer[Run SSE Server<br/>Port: specified]
    
    StdioServer --> MCPHandler[MCP Request Handler]
    HttpServer --> MCPHandler
    SseServer --> MCPHandler
    
    MCPHandler --> ToolDispatch{Tool Selection}
    
    ToolDispatch --> |analyze_file| AnalyzeFile[Comprehensive Analysis]
    ToolDispatch --> |llm_analyze_file| LLMAnalyze[LLM-Optimized Analysis]
    ToolDispatch --> |yara_scan_file| YaraScan[YARA Rule Scanning]
    ToolDispatch --> |analyze_npm_package| NPMAnalyze[NPM Security Analysis]
    ToolDispatch --> |analyze_python_package| PythonAnalyze[Python Security Analysis]
    ToolDispatch --> |analyze_java_file| JavaAnalyze[Java Analysis]
    
    StandaloneMode --> FileCheck{File Exists?}
    FileCheck --> |No| Error1[Error: File not found]
    FileCheck --> |Yes| InitMetadata[Initialize FileMetadata]
    
    AnalyzeFile --> InitMetadata
    LLMAnalyze --> InitMetadata
    
    InitMetadata --> BasicMeta[Extract Basic Metadata<br/>- Size, timestamps<br/>- Permissions<br/>- MIME type]
    
    BasicMeta --> AnalysisFlags{Check Analysis Flags}
    
    AnalysisFlags --> |--hashes| HashCalc[Calculate Hashes<br/>Concurrent]
    AnalysisFlags --> |--strings| StringExtract[Extract Strings]
    AnalysisFlags --> |--hex-dump| HexDump[Generate Hex Dump]
    AnalysisFlags --> |--verify-signatures| SigVerify[Verify Signatures]
    AnalysisFlags --> |--binary-info| BinaryParse[Parse Binary Format]
    
    HashCalc --> Aggregate[Aggregate Results]
    StringExtract --> StringTracker[Update String Tracker]
    StringTracker --> Aggregate
    HexDump --> Aggregate
    SigVerify --> Aggregate
    BinaryParse --> PackageCheck{Is Package File?}
    
    PackageCheck --> |NPM| NPMAnalyze
    PackageCheck --> |Python| PythonAnalyze
    PackageCheck --> |Java| JavaAnalyze
    PackageCheck --> |No| Aggregate
    
    NPMAnalyze --> Aggregate
    PythonAnalyze --> Aggregate
    JavaAnalyze --> Aggregate
    
    Aggregate --> CacheUpdate[Update Cache]
    CacheUpdate --> FormatOutput{Output Format?}
    
    FormatOutput --> |JSON| JSONOut[Compact JSON]
    FormatOutput --> |YAML| YAMLOut[YAML Format]
    FormatOutput --> |Pretty| PrettyOut[Pretty JSON]
    FormatOutput --> |MCP| MCPResponse[MCP Response]
    
    JSONOut --> End([Complete])
    YAMLOut --> End
    PrettyOut --> End
    MCPResponse --> End
    Error1 --> End
```

## Hash Calculation Subprocess

```mermaid
flowchart LR
    StartHash([Hash Calculation]) --> AcquireSem[Acquire Semaphore<br/>Max: 10 concurrent]
    
    AcquireSem --> SpawnTasks[Spawn Async Tasks]
    
    SpawnTasks --> MD5[Calculate MD5]
    SpawnTasks --> SHA256[Calculate SHA256]
    SpawnTasks --> SHA512[Calculate SHA512]
    SpawnTasks --> BLAKE3[Calculate BLAKE3]
    
    MD5 --> ReadFile1[Read File<br/>8KB chunks]
    SHA256 --> ReadFile2[Read File<br/>8KB chunks]
    SHA512 --> ReadFile3[Read File<br/>8KB chunks]
    BLAKE3 --> ReadFile4[Read File<br/>8KB chunks]
    
    ReadFile1 --> UpdateHash1[Update Hash State]
    ReadFile2 --> UpdateHash2[Update Hash State]
    ReadFile3 --> UpdateHash3[Update Hash State]
    ReadFile4 --> UpdateHash4[Update Hash State]
    
    UpdateHash1 --> |EOF?| Finalize1[Finalize Hash]
    UpdateHash2 --> |EOF?| Finalize2[Finalize Hash]
    UpdateHash3 --> |EOF?| Finalize3[Finalize Hash]
    UpdateHash4 --> |EOF?| Finalize4[Finalize Hash]
    
    UpdateHash1 --> |More data| ReadFile1
    UpdateHash2 --> |More data| ReadFile2
    UpdateHash3 --> |More data| ReadFile3
    UpdateHash4 --> |More data| ReadFile4
    
    Finalize1 --> ReleaseSem[Release Semaphore]
    Finalize2 --> ReleaseSem
    Finalize3 --> ReleaseSem
    Finalize4 --> ReleaseSem
    
    ReleaseSem --> ReturnHashes([Return All Hashes])
```

## String Extraction Flow

```mermaid
flowchart TD
    StartString([String Extraction]) --> CheckSize{File > 100MB?}
    
    CheckSize --> |Yes| TruncateRead[Read First 100MB]
    CheckSize --> |No| FullRead[Read Entire File]
    
    TruncateRead --> ExtractASCII[Extract ASCII Strings<br/>Min length: 4]
    FullRead --> ExtractASCII
    
    ExtractASCII --> ExtractUTF16LE[Extract UTF-16 LE]
    ExtractUTF16LE --> ExtractUTF16BE[Extract UTF-16 BE]
    
    ExtractUTF16BE --> Deduplicate[Remove Duplicates]
    
    Deduplicate --> Categorize[Categorize Strings]
    
    Categorize --> URLCat[URLs/Domains]
    Categorize --> PathCat[File Paths]
    Categorize --> APICat[API Imports]
    Categorize --> CmdCat[Commands]
    Categorize --> SuspCat[Suspicious]
    
    URLCat --> CalcEntropy[Calculate Entropy]
    PathCat --> CalcEntropy
    APICat --> CalcEntropy
    CmdCat --> CalcEntropy
    SuspCat --> CalcEntropy
    
    CalcEntropy --> UpdateTracker[Update String Tracker<br/>- Occurrences<br/>- File associations<br/>- Statistics]
    
    UpdateTracker --> LimitOutput{> 1000 strings?}
    
    LimitOutput --> |Yes| Truncate[Truncate to 1000]
    LimitOutput --> |No| ReturnAll[Return All]
    
    Truncate --> EndString([Return Strings])
    ReturnAll --> EndString
```

## Cache Operation Flow

```mermaid
flowchart TD
    CacheOp([Cache Operation]) --> OpType{Operation Type?}
    
    OpType --> |Store| StoreOp[Store Analysis]
    OpType --> |Retrieve| RetrieveOp[Retrieve Analysis]
    OpType --> |Search| SearchOp[Search Cache]
    
    StoreOp --> GenKey[Generate SHA256<br/>of file content]
    RetrieveOp --> GenKey
    
    GenKey --> AcquireLock[Acquire RwLock]
    
    AcquireLock --> |Store| CheckSize{Cache Full?<br/>Max: 10000}
    AcquireLock --> |Retrieve| LookupEntry[Lookup by SHA256]
    
    CheckSize --> |Yes| EvictLRU[Evict Oldest Entry]
    CheckSize --> |No| AddEntry[Add New Entry]
    
    EvictLRU --> AddEntry
    
    AddEntry --> UpdateStats[Update Statistics<br/>- Hit/miss ratio<br/>- Avg analysis time]
    
    UpdateStats --> ReleaseLock[Release RwLock]
    
    ReleaseLock --> AsyncSave[Spawn Async Save<br/>Non-blocking]
    
    AsyncSave --> EndCache([Complete])
    
    LookupEntry --> |Found| ReturnCached[Return Cached Result]
    LookupEntry --> |Not Found| ReturnMiss[Return Cache Miss]
    
    ReturnCached --> EndCache
    ReturnMiss --> EndCache
    
    SearchOp --> BuildQuery[Build Search Query]
    BuildQuery --> FilterEntries[Filter Entries<br/>- Tool name<br/>- File path<br/>- Date range]
    FilterEntries --> ReturnResults[Return Matches]
    ReturnResults --> EndCache
```

## Security Analysis Decision Tree

```mermaid
flowchart TD
    SecAnalysis([Security Analysis]) --> FileType{Identify File Type}
    
    FileType --> |NPM Package| NPMSec[NPM Security Check]
    FileType --> |Python Package| PySec[Python Security Check]
    FileType --> |Binary| BinSec[Binary Security Check]
    FileType --> |Other| GenSec[General Security Check]
    
    NPMSec --> CheckPackageJSON[Parse package.json]
    CheckPackageJSON --> CheckScripts{Has Install Scripts?}
    CheckScripts --> |Yes| AnalyzeScripts[Analyze for:<br/>- External downloads<br/>- Obfuscation<br/>- Env var access]
    CheckScripts --> |No| CheckDeps[Check Dependencies]
    
    AnalyzeScripts --> CheckDeps
    CheckDeps --> VulnDB[Query Vulnerability DB]
    VulnDB --> Typosquatting[Check Typosquatting]
    Typosquatting --> CalcRisk[Calculate Risk Score]
    
    PySec --> CheckSetup[Analyze setup.py]
    CheckSetup --> CheckImports[Analyze Imports:<br/>- subprocess<br/>- os.system<br/>- eval/exec]
    CheckImports --> PyVulnDB[Query Python Vuln DB]
    PyVulnDB --> PyTypo[Check Typosquatting]
    PyTypo --> CalcRisk
    
    BinSec --> CheckSigs[Verify Signatures]
    CheckSigs --> CheckImports2[Check Imports:<br/>- Crypto APIs<br/>- Network APIs<br/>- Process APIs]
    CheckImports2 --> CheckStrings[Analyze Strings:<br/>- C2 domains<br/>- Suspicious paths<br/>- Commands]
    CheckStrings --> CalcRisk
    
    GenSec --> BasicChecks[Basic Checks:<br/>- File entropy<br/>- Suspicious strings<br/>- Known patterns]
    BasicChecks --> CalcRisk
    
    CalcRisk --> RiskLevel{Risk Level?}
    
    RiskLevel --> |Critical| CriticalAlert[Flag: Critical Risk<br/>Score: 80-100]
    RiskLevel --> |High| HighAlert[Flag: High Risk<br/>Score: 60-80]
    RiskLevel --> |Medium| MedAlert[Flag: Medium Risk<br/>Score: 40-60]
    RiskLevel --> |Low| LowAlert[Flag: Low Risk<br/>Score: 0-40]
    
    CriticalAlert --> EndSec([Return Security Report])
    HighAlert --> EndSec
    MedAlert --> EndSec
    LowAlert --> EndSec
```

## Key Decision Points & Performance Optimizations

### 1. **Concurrency Control**
- Global semaphores limit resource usage
- Async operations prevent blocking
- Parallel hash calculations improve throughput

### 2. **Memory Management**
- 100MB limit on file reads for strings
- 1000 string output limit
- LRU cache eviction at 10,000 entries

### 3. **Error Recovery**
- Graceful degradation when components fail
- Optional analyses don't block core functionality
- Detailed error messages for debugging

### 4. **Performance Shortcuts**
- SHA256-based cache lookups
- Early exit for unsupported file types
- Streaming reads for large files

### 5. **Security Priorities**
- Vulnerability databases checked first
- Known malicious patterns prioritized
- Risk scoring guides analysis depth

## Architecture Insights

### What Works Well

1. **Async-First Design**: Non-blocking operations throughout
2. **Resource Pooling**: Prevents system overload
3. **Modular Analysis**: Each component independent
4. **Smart Caching**: Content-based identification
5. **Security Focus**: Multiple detection layers

### Areas for Enhancement

1. **Streaming Architecture**: For files > 100MB
2. **Plugin System**: Dynamic analyzer loading
3. **Distributed Processing**: Multi-node support
4. **ML Integration**: Advanced pattern detection
5. **Real-time Monitoring**: File system watches

### Performance Characteristics

- **Startup Time**: < 100ms
- **Small Files (< 1MB)**: < 500ms full analysis
- **Large Files (> 100MB)**: Linear scaling with size
- **Cache Hit**: < 10ms response time
- **Concurrent Files**: Up to 10 parallel analyses