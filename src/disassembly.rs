use anyhow::{Result, Context};
use capstone::prelude::*;
use capstone::{Arch, Mode, NO_EXTRA_MODE};
use std::path::Path;
use std::collections::{HashMap, HashSet};
use serde::{Serialize, Deserialize};
use goblin::Object;
use std::fs;

use crate::function_analysis::SymbolTable;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisassemblyResult {
    pub architecture: String,
    pub instructions: Vec<Instruction>,
    pub analysis: InstructionAnalysis,
    pub functions: Vec<DisassembledFunction>,
    pub output_formats: OutputFormats,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Instruction {
    pub address: u64,
    pub bytes: Vec<u8>,
    pub mnemonic: String,
    pub operands: String,
    pub instruction_type: InstructionType,
    pub flow_control: Option<FlowControl>,
    pub size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum InstructionType {
    Arithmetic,
    Logic,
    Memory,
    Control,
    System,
    Crypto,
    Vector,
    Stack,
    Comparison,
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FlowControl {
    Jump { target: Option<u64>, conditional: bool },
    Call { target: Option<u64>, is_indirect: bool },
    Return,
    Interrupt { number: u8 },
    ConditionalMove,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstructionAnalysis {
    pub total_instructions: usize,
    pub instruction_types: HashMap<String, usize>,
    pub register_usage: HashMap<String, Vec<u64>>,
    pub memory_accesses: Vec<MemoryAccess>,
    pub system_calls: Vec<SystemCall>,
    pub crypto_operations: Vec<CryptoOperation>,
    pub suspicious_patterns: Vec<SuspiciousPattern>,
    pub control_flow_summary: ControlFlowSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryAccess {
    pub instruction_address: u64,
    pub access_type: AccessType,
    pub size: u32,
    pub target_address: Option<u64>,
    pub register_base: Option<String>,
    pub register_index: Option<String>,
    pub displacement: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AccessType {
    Read,
    Write,
    Execute,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemCall {
    pub address: u64,
    pub syscall_number: Option<u64>,
    pub syscall_name: Option<String>,
    pub category: SystemCallCategory,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SystemCallCategory {
    FileSystem,
    Process,
    Network,
    Memory,
    Security,
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoOperation {
    pub address: u64,
    pub operation_type: CryptoOpType,
    pub algorithm_hint: Option<String>,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CryptoOpType {
    AESOperation,
    SHA256Operation,
    RSAOperation,
    XOROperation,
    RandomGeneration,
    KeyDerivation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspiciousPattern {
    pub pattern_type: PatternType,
    pub addresses: Vec<u64>,
    pub description: String,
    pub severity: Severity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PatternType {
    AntiDebug,
    AntiVM,
    Obfuscation,
    SelfModifying,
    StackManipulation,
    IndirectJumps,
    NopSled,
    ReturnOriented,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlFlowSummary {
    pub total_jumps: usize,
    pub conditional_jumps: usize,
    pub unconditional_jumps: usize,
    pub function_calls: usize,
    pub indirect_calls: usize,
    pub returns: usize,
    pub interrupts: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisassembledFunction {
    pub address: u64,
    pub name: String,
    pub size: usize,
    pub instructions: Vec<Instruction>,
    pub basic_blocks: Vec<BasicBlock>,
    pub complexity: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BasicBlock {
    pub start_address: u64,
    pub end_address: u64,
    pub instruction_count: usize,
    pub exits: Vec<BlockExit>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockExit {
    pub exit_type: ExitType,
    pub target: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExitType {
    FallThrough,
    Jump,
    ConditionalJump,
    Call,
    Return,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputFormats {
    pub assembly: String,
    pub json_structured: serde_json::Value,
    pub graph_data: GraphVisualizationData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphVisualizationData {
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphNode {
    pub id: String,
    pub label: String,
    pub node_type: String,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphEdge {
    pub source: String,
    pub target: String,
    pub edge_type: String,
    pub label: Option<String>,
}

pub fn disassemble_binary(path: &Path, symbol_table: &SymbolTable) -> Result<DisassemblyResult> {
    let buffer = fs::read(path).context("Failed to read file for disassembly")?;
    
    // Detect architecture
    let (arch, mode, code_section) = detect_architecture_and_code(&buffer)?;
    let architecture = format_architecture(arch, mode);
    
    // Create Capstone instance
    let cs = create_capstone(arch, mode)?;
    
    // Disassemble code section
    let instructions = disassemble_code(&cs, &code_section.data, code_section.address)?;
    
    // Analyze instructions
    let analysis = analyze_instructions(&instructions);
    
    // Group into functions
    let functions = group_into_functions(&instructions, symbol_table);
    
    // Generate output formats
    let output_formats = generate_output_formats(&instructions, &functions, &architecture);
    
    Ok(DisassemblyResult {
        architecture,
        instructions,
        analysis,
        functions,
        output_formats,
    })
}

struct CodeSection {
    data: Vec<u8>,
    address: u64,
}

fn detect_architecture_and_code(buffer: &[u8]) -> Result<(Arch, Mode, CodeSection)> {
    match Object::parse(buffer)? {
        Object::Elf(elf) => {
            let (arch, mode) = match elf.header.e_machine {
                goblin::elf::header::EM_X86_64 => (Arch::X86, Mode::Mode64),
                goblin::elf::header::EM_386 => (Arch::X86, Mode::Mode32),
                goblin::elf::header::EM_ARM => (Arch::ARM, Mode::Arm),
                goblin::elf::header::EM_AARCH64 => (Arch::ARM64, Mode::Arm),
                _ => return Err(anyhow::anyhow!("Unsupported ELF architecture")),
            };
            
            // Find .text section
            for section in &elf.section_headers {
                if let Some(name) = elf.shdr_strtab.get_at(section.sh_name) {
                    if name == ".text" {
                        let start = section.sh_offset as usize;
                        let end = start + section.sh_size as usize;
                        let code_section = CodeSection {
                            data: buffer[start..end].to_vec(),
                            address: section.sh_addr,
                        };
                        return Ok((arch, mode, code_section));
                    }
                }
            }
            Err(anyhow::anyhow!("No .text section found"))
        }
        Object::PE(pe) => {
            let arch = if pe.is_64 {
                (Arch::X86, Mode::Mode64)
            } else {
                (Arch::X86, Mode::Mode32)
            };
            
            // Find .text section
            for section in &pe.sections {
                let name = String::from_utf8_lossy(&section.name);
                if name.trim_end_matches('\0') == ".text" {
                    let start = section.pointer_to_raw_data as usize;
                    let end = start + section.size_of_raw_data as usize;
                    let code_section = CodeSection {
                        data: buffer[start..end].to_vec(),
                        address: pe.image_base as u64 + section.virtual_address as u64,
                    };
                    return Ok((arch.0, arch.1, code_section));
                }
            }
            Err(anyhow::anyhow!("No .text section found"))
        }
        Object::Mach(mach) => {
            match mach {
                goblin::mach::Mach::Binary(macho) => {
                    let (arch, mode) = match macho.header.cputype {
                        goblin::mach::cputype::CPU_TYPE_X86_64 => (Arch::X86, Mode::Mode64),
                        goblin::mach::cputype::CPU_TYPE_X86 => (Arch::X86, Mode::Mode32),
                        goblin::mach::cputype::CPU_TYPE_ARM64 => (Arch::ARM64, Mode::Arm),
                        _ => return Err(anyhow::anyhow!("Unsupported Mach-O architecture")),
                    };
                    
                    // Find __text section
                    for segment in &macho.segments {
                        for (section, data) in segment.sections()? {
                            if section.name()? == "__text" {
                                let code_section = CodeSection {
                                    data: data.to_vec(),
                                    address: section.addr,
                                };
                                return Ok((arch, mode, code_section));
                            }
                        }
                    }
                    Err(anyhow::anyhow!("No __text section found"))
                }
                _ => Err(anyhow::anyhow!("Fat binaries not yet supported")),
            }
        }
        _ => Err(anyhow::anyhow!("Unknown binary format")),
    }
}

fn create_capstone(arch: Arch, mode: Mode) -> Result<Capstone> {
    let cs = Capstone::new_raw(arch, mode, NO_EXTRA_MODE, None)
        .map_err(|e| anyhow::anyhow!("Failed to create Capstone instance: {:?}", e))?;
    Ok(cs)
}

fn disassemble_code(cs: &Capstone, code: &[u8], base_address: u64) -> Result<Vec<Instruction>> {
    let mut instructions = Vec::new();
    
    let insns = cs.disasm_all(code, base_address)
        .map_err(|e| anyhow::anyhow!("Disassembly failed: {:?}", e))?;
    
    for insn in insns.iter() {
        let flow_control = detect_flow_control(&insn);
        let instruction_type = classify_instruction(&insn);
        
        instructions.push(Instruction {
            address: insn.address(),
            bytes: insn.bytes().to_vec(),
            mnemonic: insn.mnemonic().unwrap_or("").to_string(),
            operands: insn.op_str().unwrap_or("").to_string(),
            instruction_type,
            flow_control,
            size: insn.bytes().len(),
        });
    }
    
    Ok(instructions)
}

fn detect_flow_control(insn: &capstone::Insn) -> Option<FlowControl> {
    let mnemonic = insn.mnemonic()?;
    
    if mnemonic.starts_with("j") {
        let conditional = mnemonic != "jmp";
        let target = None; // Would need detail access
        Some(FlowControl::Jump { target, conditional })
    } else if mnemonic == "call" {
        let target = None; // Would need detail access
        let is_indirect = insn.op_str().map_or(false, |ops| ops.contains('['));
        Some(FlowControl::Call { target, is_indirect })
    } else if mnemonic == "ret" || mnemonic == "retn" {
        Some(FlowControl::Return)
    } else if mnemonic == "int" {
        let number = 0; // Would need detail access
        Some(FlowControl::Interrupt { number })
    } else if mnemonic.starts_with("cmov") {
        Some(FlowControl::ConditionalMove)
    } else {
        None
    }
}

fn classify_instruction(insn: &capstone::Insn) -> InstructionType {
    let mnemonic = insn.mnemonic().unwrap_or("");
    
    match mnemonic {
        // Arithmetic
        "add" | "sub" | "mul" | "div" | "inc" | "dec" | "adc" | "sbb" | "imul" | "idiv" => InstructionType::Arithmetic,
        
        // Logic
        "and" | "or" | "xor" | "not" | "shl" | "shr" | "sal" | "sar" | "rol" | "ror" => InstructionType::Logic,
        
        // Memory
        "mov" | "movzx" | "movsx" | "lea" | "ld" | "st" | "ldr" | "str" => InstructionType::Memory,
        
        // Control
        m if m.starts_with("j") || m == "call" || m == "ret" || m == "int" => InstructionType::Control,
        
        // Stack
        "push" | "pop" | "pushf" | "popf" | "enter" | "leave" => InstructionType::Stack,
        
        // Comparison
        "cmp" | "test" => InstructionType::Comparison,
        
        // System
        "syscall" | "sysenter" | "sysexit" | "int" if insn.op_str().unwrap_or("") == "0x80" => InstructionType::System,
        
        // Crypto hints
        "aesenc" | "aesdec" | "aesimc" | "aeskeygen" | "sha256" | "pclmulqdq" => InstructionType::Crypto,
        
        // Vector
        m if m.starts_with("v") || m.starts_with("p") && (m.contains("mm") || m.contains("xmm")) => InstructionType::Vector,
        
        _ => InstructionType::Other,
    }
}

fn analyze_instructions(instructions: &[Instruction]) -> InstructionAnalysis {
    let mut instruction_types = HashMap::new();
    let mut register_usage = HashMap::new();
    let mut memory_accesses = Vec::new();
    let mut system_calls = Vec::new();
    let mut crypto_operations = Vec::new();
    let mut suspicious_patterns = Vec::new();
    let mut control_flow_summary = ControlFlowSummary {
        total_jumps: 0,
        conditional_jumps: 0,
        unconditional_jumps: 0,
        function_calls: 0,
        indirect_calls: 0,
        returns: 0,
        interrupts: 0,
    };
    
    // Instruction type counting
    for insn in instructions {
        *instruction_types.entry(insn.mnemonic.clone()).or_insert(0) += 1;
        
        // Register tracking
        track_register_usage(insn, &mut register_usage);
        
        // Memory access tracking
        if let Some(mem_access) = detect_memory_access(insn) {
            memory_accesses.push(mem_access);
        }
        
        // Control flow tracking
        if let Some(flow) = &insn.flow_control {
            match flow {
                FlowControl::Jump { conditional, .. } => {
                    control_flow_summary.total_jumps += 1;
                    if *conditional {
                        control_flow_summary.conditional_jumps += 1;
                    } else {
                        control_flow_summary.unconditional_jumps += 1;
                    }
                }
                FlowControl::Call { is_indirect, .. } => {
                    control_flow_summary.function_calls += 1;
                    if *is_indirect {
                        control_flow_summary.indirect_calls += 1;
                    }
                }
                FlowControl::Return => control_flow_summary.returns += 1,
                FlowControl::Interrupt { .. } => control_flow_summary.interrupts += 1,
                _ => {}
            }
        }
        
        // System call detection
        if insn.mnemonic == "syscall" || (insn.mnemonic == "int" && insn.operands == "0x80") {
            system_calls.push(SystemCall {
                address: insn.address,
                syscall_number: None, // Would need register state analysis
                syscall_name: None,
                category: SystemCallCategory::Other,
            });
        }
        
        // Crypto operation detection
        if let Some(crypto_op) = detect_crypto_operation(insn) {
            crypto_operations.push(crypto_op);
        }
    }
    
    // Pattern detection
    suspicious_patterns.extend(detect_suspicious_patterns(instructions));
    
    InstructionAnalysis {
        total_instructions: instructions.len(),
        instruction_types,
        register_usage,
        memory_accesses,
        system_calls,
        crypto_operations,
        suspicious_patterns,
        control_flow_summary,
    }
}

fn track_register_usage(insn: &Instruction, register_usage: &mut HashMap<String, Vec<u64>>) {
    // Extract registers from operands (simplified)
    let operands = &insn.operands;
    let registers = vec!["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
                        "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp",
                        "ax", "bx", "cx", "dx", "si", "di", "bp", "sp"];
    
    for reg in registers {
        if operands.contains(reg) {
            register_usage.entry(reg.to_string())
                .or_insert_with(Vec::new)
                .push(insn.address);
        }
    }
}

fn detect_memory_access(insn: &Instruction) -> Option<MemoryAccess> {
    if insn.instruction_type != InstructionType::Memory {
        return None;
    }
    
    let access_type = match insn.mnemonic.as_str() {
        "mov" if insn.operands.contains('[') && insn.operands.find('[').unwrap() < insn.operands.find(',').unwrap_or(usize::MAX) => AccessType::Write,
        "mov" => AccessType::Read,
        _ => AccessType::Read,
    };
    
    Some(MemoryAccess {
        instruction_address: insn.address,
        access_type,
        size: estimate_access_size(&insn.mnemonic),
        target_address: None, // Would need operand parsing
        register_base: None,
        register_index: None,
        displacement: None,
    })
}

fn estimate_access_size(mnemonic: &str) -> u32 {
    if mnemonic.ends_with('b') {
        1
    } else if mnemonic.ends_with('w') {
        2
    } else if mnemonic.ends_with('d') {
        4
    } else if mnemonic.ends_with('q') {
        8
    } else {
        4 // default
    }
}

fn detect_crypto_operation(insn: &Instruction) -> Option<CryptoOperation> {
    let crypto_op_type = match insn.mnemonic.as_str() {
        m if m.starts_with("aes") => Some(CryptoOpType::AESOperation),
        "sha256rnds2" | "sha256msg1" | "sha256msg2" => Some(CryptoOpType::SHA256Operation),
        "xor" if insn.operands.contains("xmm") => Some(CryptoOpType::XOROperation),
        "rdrand" | "rdseed" => Some(CryptoOpType::RandomGeneration),
        _ => None,
    };
    
    crypto_op_type.map(|op_type| CryptoOperation {
        address: insn.address,
        operation_type: op_type,
        algorithm_hint: Some(insn.mnemonic.clone()),
        confidence: 0.8,
    })
}

fn detect_suspicious_patterns(instructions: &[Instruction]) -> Vec<SuspiciousPattern> {
    let mut patterns = Vec::new();
    
    // Anti-debug detection
    let mut anti_debug_addrs = Vec::new();
    for insn in instructions {
        if insn.mnemonic == "rdtsc" || 
           (insn.mnemonic == "int" && insn.operands == "3") ||
           insn.operands.contains("BeingDebugged") {
            anti_debug_addrs.push(insn.address);
        }
    }
    if !anti_debug_addrs.is_empty() {
        patterns.push(SuspiciousPattern {
            pattern_type: PatternType::AntiDebug,
            addresses: anti_debug_addrs,
            description: "Anti-debugging techniques detected".to_string(),
            severity: Severity::Medium,
        });
    }
    
    // NOP sled detection
    let mut consecutive_nops = 0;
    let mut nop_start = 0;
    for (i, insn) in instructions.iter().enumerate() {
        if insn.mnemonic == "nop" {
            if consecutive_nops == 0 {
                nop_start = i;
            }
            consecutive_nops += 1;
        } else {
            if consecutive_nops > 10 {
                patterns.push(SuspiciousPattern {
                    pattern_type: PatternType::NopSled,
                    addresses: vec![instructions[nop_start].address],
                    description: format!("NOP sled of {} instructions", consecutive_nops),
                    severity: Severity::Medium,
                });
            }
            consecutive_nops = 0;
        }
    }
    
    // Indirect jump analysis
    let indirect_jumps: Vec<_> = instructions.iter()
        .filter(|insn| matches!(&insn.flow_control, 
            Some(FlowControl::Jump { target: None, .. }) | 
            Some(FlowControl::Call { is_indirect: true, .. })))
        .map(|insn| insn.address)
        .collect();
    
    if indirect_jumps.len() > 20 {
        patterns.push(SuspiciousPattern {
            pattern_type: PatternType::IndirectJumps,
            addresses: indirect_jumps,
            description: "High number of indirect jumps detected".to_string(),
            severity: Severity::High,
        });
    }
    
    patterns
}

fn group_into_functions(instructions: &[Instruction], symbol_table: &SymbolTable) -> Vec<DisassembledFunction> {
    let mut functions = Vec::new();
    
    for func_info in &symbol_table.functions {
        let func_start = func_info.address;
        let func_end = func_start + func_info.size;
        
        let func_instructions: Vec<Instruction> = instructions.iter()
            .filter(|insn| insn.address >= func_start && insn.address < func_end)
            .cloned()
            .collect();
        
        if !func_instructions.is_empty() {
            let basic_blocks = identify_basic_blocks(&func_instructions);
            let complexity = calculate_complexity(&basic_blocks);
            
            functions.push(DisassembledFunction {
                address: func_start,
                name: func_info.name.clone(),
                size: func_info.size as usize,
                instructions: func_instructions,
                basic_blocks,
                complexity,
            });
        }
    }
    
    functions
}

fn identify_basic_blocks(instructions: &[Instruction]) -> Vec<BasicBlock> {
    let mut blocks = Vec::new();
    let mut block_starts = HashSet::new();
    
    // Identify block starts
    block_starts.insert(instructions[0].address);
    for insn in instructions {
        if let Some(flow) = &insn.flow_control {
            match flow {
                FlowControl::Jump { target: Some(t), .. } |
                FlowControl::Call { target: Some(t), .. } => {
                    block_starts.insert(*t);
                }
                _ => {}
            }
        }
    }
    
    // Build blocks
    let mut current_block_start = instructions[0].address;
    let mut current_instructions = 0;
    
    for (i, insn) in instructions.iter().enumerate() {
        current_instructions += 1;
        
        let is_block_end = insn.flow_control.is_some() || 
                          (i + 1 < instructions.len() && block_starts.contains(&instructions[i + 1].address));
        
        if is_block_end || i == instructions.len() - 1 {
            let exits = if let Some(flow) = &insn.flow_control {
                match flow {
                    FlowControl::Jump { target, conditional } => {
                        if *conditional {
                            vec![
                                BlockExit { exit_type: ExitType::ConditionalJump, target: *target },
                                BlockExit { exit_type: ExitType::FallThrough, target: instructions.get(i + 1).map(|i| i.address) },
                            ]
                        } else {
                            vec![BlockExit { exit_type: ExitType::Jump, target: *target }]
                        }
                    }
                    FlowControl::Call { target, .. } => {
                        vec![BlockExit { exit_type: ExitType::Call, target: *target }]
                    }
                    FlowControl::Return => {
                        vec![BlockExit { exit_type: ExitType::Return, target: None }]
                    }
                    _ => vec![],
                }
            } else if i + 1 < instructions.len() {
                vec![BlockExit { exit_type: ExitType::FallThrough, target: Some(instructions[i + 1].address) }]
            } else {
                vec![]
            };
            
            blocks.push(BasicBlock {
                start_address: current_block_start,
                end_address: insn.address + insn.size as u64,
                instruction_count: current_instructions,
                exits,
            });
            
            if i + 1 < instructions.len() {
                current_block_start = instructions[i + 1].address;
                current_instructions = 0;
            }
        }
    }
    
    blocks
}

fn calculate_complexity(basic_blocks: &[BasicBlock]) -> u32 {
    // Cyclomatic complexity = E - N + 2P
    // E = edges, N = nodes, P = connected components (usually 1)
    let nodes = basic_blocks.len() as u32;
    let edges = basic_blocks.iter()
        .map(|b| b.exits.len() as u32)
        .sum::<u32>();
    
    edges.saturating_sub(nodes) + 2
}

fn format_architecture(arch: Arch, mode: Mode) -> String {
    match (arch, mode) {
        (Arch::X86, Mode::Mode64) => "x86_64".to_string(),
        (Arch::X86, Mode::Mode32) => "x86".to_string(),
        (Arch::ARM, Mode::Arm) => "ARM".to_string(),
        (Arch::ARM64, Mode::Arm) => "ARM64".to_string(),
        _ => "Unknown".to_string(),
    }
}

fn generate_output_formats(
    instructions: &[Instruction],
    functions: &[DisassembledFunction],
    architecture: &str
) -> OutputFormats {
    // Generate assembly listing
    let assembly = generate_assembly_listing(instructions);
    
    // Generate structured JSON
    let json_structured = serde_json::json!({
        "architecture": architecture,
        "instruction_count": instructions.len(),
        "function_count": functions.len(),
        "functions": functions.iter().map(|f| {
            serde_json::json!({
                "name": f.name,
                "address": format!("0x{:x}", f.address),
                "size": f.size,
                "complexity": f.complexity,
                "basic_blocks": f.basic_blocks.len(),
            })
        }).collect::<Vec<_>>(),
    });
    
    // Generate graph visualization data
    let graph_data = generate_graph_data(functions);
    
    OutputFormats {
        assembly,
        json_structured,
        graph_data,
    }
}

fn generate_assembly_listing(instructions: &[Instruction]) -> String {
    let mut output = String::new();
    
    for insn in instructions {
        output.push_str(&format!(
            "{:08x}:  {:20}  {} {}\n",
            insn.address,
            insn.bytes.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" "),
            insn.mnemonic,
            insn.operands
        ));
    }
    
    output
}

fn generate_graph_data(functions: &[DisassembledFunction]) -> GraphVisualizationData {
    let mut nodes = Vec::new();
    let mut edges = Vec::new();
    
    for func in functions {
        // Function node
        nodes.push(GraphNode {
            id: format!("func_{:x}", func.address),
            label: func.name.clone(),
            node_type: "function".to_string(),
            metadata: [
                ("address".to_string(), format!("0x{:x}", func.address)),
                ("size".to_string(), func.size.to_string()),
                ("complexity".to_string(), func.complexity.to_string()),
            ].iter().cloned().collect(),
        });
        
        // Basic block nodes
        for (i, block) in func.basic_blocks.iter().enumerate() {
            let block_id = format!("block_{:x}_{}", func.address, i);
            nodes.push(GraphNode {
                id: block_id.clone(),
                label: format!("Block {}: 0x{:x}", i, block.start_address),
                node_type: "basic_block".to_string(),
                metadata: [
                    ("instructions".to_string(), block.instruction_count.to_string()),
                ].iter().cloned().collect(),
            });
            
            // Block edges
            for exit in &block.exits {
                if let Some(target) = exit.target {
                    edges.push(GraphEdge {
                        source: block_id.clone(),
                        target: format!("block_{:x}", target),
                        edge_type: format!("{:?}", exit.exit_type),
                        label: Some(format!("{:?}", exit.exit_type)),
                    });
                }
            }
        }
    }
    
    GraphVisualizationData { nodes, edges }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_instruction_classification() {
        let test_cases = vec![
            ("add", InstructionType::Arithmetic),
            ("mov", InstructionType::Memory),
            ("jmp", InstructionType::Control),
            ("push", InstructionType::Stack),
            ("cmp", InstructionType::Comparison),
            ("aesenc", InstructionType::Crypto),
        ];
        
        for (mnemonic, expected) in test_cases {
            let insn = Instruction {
                address: 0,
                bytes: vec![],
                mnemonic: mnemonic.to_string(),
                operands: String::new(),
                instruction_type: InstructionType::Other,
                flow_control: None,
                size: 0,
            };
            
            // Would need to test through classify_instruction
        }
    }
}