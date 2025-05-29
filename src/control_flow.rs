use anyhow::{Result, anyhow};
use capstone::prelude::*;
use goblin::Object;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::File;
use std::io::Read;
use std::path::Path;

use crate::function_analysis::{FunctionInfo, SymbolTable};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ControlFlowGraph {
    pub function_address: u64,
    pub function_name: String,
    pub basic_blocks: Vec<BasicBlock>,
    pub edges: Vec<CfgEdge>,
    pub entry_block: usize,
    pub exit_blocks: Vec<usize>,
    pub loops: Vec<Loop>,
    pub complexity: ControlFlowMetrics,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BasicBlock {
    pub id: usize,
    pub start_address: u64,
    pub end_address: u64,
    pub instructions: Vec<Instruction>,
    pub successors: Vec<usize>,
    pub predecessors: Vec<usize>,
    pub block_type: BlockType,
    pub instruction_count: usize,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum BlockType {
    Entry,
    Exit,
    Normal,
    LoopHeader,
    LoopBody,
    Conditional,
    Call,
    Return,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Instruction {
    pub address: u64,
    pub bytes: Vec<u8>,
    pub mnemonic: String,
    pub operands: String,
    pub instruction_type: InstructionType,
    pub flow_control: FlowControl,
    pub size: usize,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum InstructionType {
    Arithmetic,
    Logic,
    Memory,
    Control,
    System,
    Call,
    Return,
    Jump,
    Conditional,
    Nop,
    Other,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum FlowControl {
    Fall,          // Falls through to next instruction
    Jump(u64),     // Unconditional jump to address
    Branch(u64),   // Conditional branch to address
    Call(u64),     // Function call to address
    Return,        // Return from function
    Indirect,      // Indirect jump/call
    Halt,          // Stops execution
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CfgEdge {
    pub from_block: usize,
    pub to_block: usize,
    pub edge_type: EdgeType,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum EdgeType {
    Fall,          // Sequential execution
    Jump,          // Unconditional jump
    Branch,        // Conditional branch
    Call,          // Function call
    Return,        // Return edge
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Loop {
    pub header_block: usize,
    pub body_blocks: Vec<usize>,
    pub exit_blocks: Vec<usize>,
    pub loop_type: LoopType,
    pub nesting_level: usize,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum LoopType {
    Natural,       // Natural loop with single entry
    Irreducible,   // Multiple entry points
    DoWhile,       // Test at end
    While,         // Test at beginning
    For,           // Counted loop
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ControlFlowMetrics {
    pub cyclomatic_complexity: u32,
    pub cognitive_complexity: u32,
    pub nesting_depth: u32,
    pub basic_block_count: usize,
    pub edge_count: usize,
    pub loop_count: usize,
    pub unreachable_blocks: Vec<usize>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ControlFlowAnalysis {
    pub cfgs: Vec<ControlFlowGraph>,
    pub overall_metrics: OverallMetrics,
    pub analysis_stats: AnalysisStats,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct OverallMetrics {
    pub total_functions: usize,
    pub analyzed_functions: usize,
    pub total_basic_blocks: usize,
    pub average_complexity: f64,
    pub max_complexity: u32,
    pub function_with_max_complexity: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AnalysisStats {
    pub analysis_duration: u64, // milliseconds
    pub bytes_analyzed: u64,
    pub instructions_analyzed: usize,
    pub errors: Vec<String>,
}

pub struct ControlFlowAnalyzer {
    capstone: Capstone,
}

impl ControlFlowAnalyzer {
    pub fn new_x86_64() -> Result<Self> {
        let capstone = Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode64)
            .syntax(arch::x86::ArchSyntax::Intel)
            .detail(true)
            .build()
            .map_err(|e| anyhow!("Failed to build x86_64 capstone engine: {:?}", e))?;

        Ok(Self { capstone })
    }

    pub fn analyze_functions(
        &self,
        binary_data: &[u8],
        symbol_table: &SymbolTable,
        text_section_offset: u64,
        text_section_addr: u64,
    ) -> Result<ControlFlowAnalysis> {
        let start_time = std::time::Instant::now();
        let mut cfgs = Vec::new();
        let mut errors = Vec::new();
        let mut total_instructions = 0;

        // Only analyze exported functions with valid sizes
        let functions_to_analyze: Vec<&FunctionInfo> = symbol_table
            .functions
            .iter()
            .filter(|f| f.is_exported && f.size > 0 && f.address >= text_section_addr)
            .collect();

        for function in &functions_to_analyze {
            // Calculate the offset within the binary file
            let file_offset = (function.address - text_section_addr + text_section_offset) as usize;
            
            // Ensure we don't read beyond the file
            if file_offset >= binary_data.len() {
                errors.push(format!("Function {} offset {} beyond file size", function.name, file_offset));
                continue;
            }

            let function_size = std::cmp::min(function.size as usize, binary_data.len() - file_offset);
            let function_bytes = &binary_data[file_offset..file_offset + function_size];

            match self.analyze_function(function, function_bytes) {
                Ok(cfg) => {
                    total_instructions += cfg.basic_blocks.iter().map(|bb| bb.instruction_count).sum::<usize>();
                    cfgs.push(cfg);
                }
                Err(e) => {
                    errors.push(format!("Failed to analyze function {}: {}", function.name, e));
                }
            }
        }

        let duration = start_time.elapsed().as_millis() as u64;

        // Calculate overall metrics
        let total_basic_blocks = cfgs.iter().map(|cfg| cfg.basic_blocks.len()).sum();
        let average_complexity = if cfgs.is_empty() {
            0.0
        } else {
            cfgs.iter().map(|cfg| cfg.complexity.cyclomatic_complexity as f64).sum::<f64>() / cfgs.len() as f64
        };

        let (max_complexity, function_with_max_complexity) = cfgs
            .iter()
            .max_by_key(|cfg| cfg.complexity.cyclomatic_complexity)
            .map(|cfg| (cfg.complexity.cyclomatic_complexity, Some(cfg.function_name.clone())))
            .unwrap_or((0, None));

        let analyzed_functions = cfgs.len();
        
        Ok(ControlFlowAnalysis {
            cfgs,
            overall_metrics: OverallMetrics {
                total_functions: functions_to_analyze.len(),
                analyzed_functions,
                total_basic_blocks,
                average_complexity,
                max_complexity,
                function_with_max_complexity,
            },
            analysis_stats: AnalysisStats {
                analysis_duration: duration,
                bytes_analyzed: binary_data.len() as u64,
                instructions_analyzed: total_instructions,
                errors,
            },
        })
    }

    fn analyze_function(&self, function: &FunctionInfo, function_bytes: &[u8]) -> Result<ControlFlowGraph> {
        // Disassemble the function
        let instructions = self.disassemble_function(function_bytes, function.address)?;
        
        if instructions.is_empty() {
            return Err(anyhow!("No instructions found in function"));
        }

        // Find basic block boundaries
        let block_boundaries = self.find_basic_block_boundaries(&instructions);
        
        // Create basic blocks
        let basic_blocks = self.create_basic_blocks(&instructions, &block_boundaries);
        
        // Build control flow edges
        let edges = self.build_control_flow_edges(&basic_blocks);
        
        // Detect loops
        let loops = self.detect_loops(&basic_blocks, &edges);
        
        // Calculate complexity metrics
        let complexity = self.calculate_complexity_metrics(&basic_blocks, &edges, &loops);
        
        // Determine entry and exit blocks
        let entry_block = 0; // First block is always entry
        let exit_blocks = self.find_exit_blocks(&basic_blocks);

        Ok(ControlFlowGraph {
            function_address: function.address,
            function_name: function.name.clone(),
            basic_blocks,
            edges,
            entry_block,
            exit_blocks,
            loops,
            complexity,
        })
    }

    fn disassemble_function(&self, bytes: &[u8], base_address: u64) -> Result<Vec<Instruction>> {
        let instructions = self.capstone.disasm_all(bytes, base_address)
            .map_err(|e| anyhow!("Failed to disassemble: {:?}", e))?;
        
        let mut result = Vec::new();

        for insn in instructions.as_ref() {
            let instruction_type = self.classify_instruction(&insn);
            let flow_control = self.analyze_flow_control(&insn);

            result.push(Instruction {
                address: insn.address(),
                bytes: insn.bytes().to_vec(),
                mnemonic: insn.mnemonic().unwrap_or("").to_string(),
                operands: insn.op_str().unwrap_or("").to_string(),
                instruction_type,
                flow_control,
                size: insn.bytes().len(),
            });
        }

        Ok(result)
    }

    fn classify_instruction(&self, insn: &capstone::Insn) -> InstructionType {
        let mnemonic = insn.mnemonic().unwrap_or("");
        
        match mnemonic {
            // Control flow instructions
            "jmp" | "je" | "jne" | "jz" | "jnz" | "jg" | "jge" | "jl" | "jle" | 
            "ja" | "jae" | "jb" | "jbe" | "jo" | "jno" | "js" | "jns" | "jp" | "jnp" => InstructionType::Jump,
            
            // Conditional jumps
            "test" | "cmp" => InstructionType::Conditional,
            
            // Function calls and returns
            "call" => InstructionType::Call,
            "ret" | "retf" | "retn" => InstructionType::Return,
            
            // Arithmetic operations
            "add" | "sub" | "mul" | "div" | "inc" | "dec" | "imul" | "idiv" | "neg" => InstructionType::Arithmetic,
            
            // Logic operations
            "and" | "or" | "xor" | "not" | "shl" | "shr" | "sal" | "sar" => InstructionType::Logic,
            
            // Memory operations
            "mov" | "lea" | "push" | "pop" | "movsb" | "movsw" | "movsd" | "movsq" => InstructionType::Memory,
            
            // No operation
            "nop" => InstructionType::Nop,
            
            // System calls and interrupts
            "syscall" | "int" | "sysenter" | "sysexit" => InstructionType::System,
            
            _ => InstructionType::Other,
        }
    }

    fn analyze_flow_control(&self, insn: &capstone::Insn) -> FlowControl {
        let mnemonic = insn.mnemonic().unwrap_or("");
        
        match mnemonic {
            "ret" | "retf" | "retn" => FlowControl::Return,
            "jmp" => {
                // Try to extract target address for direct jumps
                if let Some(op_str) = insn.op_str() {
                    if let Ok(addr) = u64::from_str_radix(op_str.trim_start_matches("0x"), 16) {
                        FlowControl::Jump(addr)
                    } else {
                        FlowControl::Indirect
                    }
                } else {
                    FlowControl::Indirect
                }
            }
            "je" | "jne" | "jz" | "jnz" | "jg" | "jge" | "jl" | "jle" | 
            "ja" | "jae" | "jb" | "jbe" | "jo" | "jno" | "js" | "jns" | "jp" | "jnp" => {
                // Try to extract target address for conditional branches
                if let Some(op_str) = insn.op_str() {
                    if let Ok(addr) = u64::from_str_radix(op_str.trim_start_matches("0x"), 16) {
                        FlowControl::Branch(addr)
                    } else {
                        FlowControl::Indirect
                    }
                } else {
                    FlowControl::Indirect
                }
            }
            "call" => {
                // Try to extract target address for direct calls
                if let Some(op_str) = insn.op_str() {
                    if let Ok(addr) = u64::from_str_radix(op_str.trim_start_matches("0x"), 16) {
                        FlowControl::Call(addr)
                    } else {
                        FlowControl::Indirect
                    }
                } else {
                    FlowControl::Indirect
                }
            }
            "hlt" => FlowControl::Halt,
            _ => FlowControl::Fall,
        }
    }

    fn find_basic_block_boundaries(&self, instructions: &[Instruction]) -> HashSet<u64> {
        let mut boundaries = HashSet::new();
        
        // First instruction is always a boundary
        if let Some(first) = instructions.first() {
            boundaries.insert(first.address);
        }

        for (i, instruction) in instructions.iter().enumerate() {
            match &instruction.flow_control {
                FlowControl::Jump(target) | FlowControl::Branch(target) | FlowControl::Call(target) => {
                    // Target of jump/branch/call is a boundary
                    boundaries.insert(*target);
                    
                    // For conditional branches, the next instruction is also a boundary
                    if matches!(instruction.flow_control, FlowControl::Branch(_)) {
                        if let Some(next_insn) = instructions.get(i + 1) {
                            boundaries.insert(next_insn.address);
                        }
                    }
                }
                FlowControl::Return | FlowControl::Halt => {
                    // Instruction after return/halt is a boundary (if it exists)
                    if let Some(next_insn) = instructions.get(i + 1) {
                        boundaries.insert(next_insn.address);
                    }
                }
                _ => {}
            }
        }

        boundaries
    }

    fn create_basic_blocks(&self, instructions: &[Instruction], boundaries: &HashSet<u64>) -> Vec<BasicBlock> {
        let mut basic_blocks = Vec::new();
        let mut current_block_instructions: Vec<Instruction> = Vec::new();
        let mut block_id = 0;
        let mut block_start_addr = 0;

        for instruction in instructions {
            // Start a new block if this address is a boundary
            if boundaries.contains(&instruction.address) && !current_block_instructions.is_empty() {
                // Finish the current block
                let end_addr = current_block_instructions.last().unwrap().address + 
                              current_block_instructions.last().unwrap().size as u64;
                
                let block_type = self.determine_block_type(&current_block_instructions);
                
                basic_blocks.push(BasicBlock {
                    id: block_id,
                    start_address: block_start_addr,
                    end_address: end_addr,
                    instruction_count: current_block_instructions.len(),
                    instructions: current_block_instructions.clone(),
                    successors: Vec::new(),
                    predecessors: Vec::new(),
                    block_type,
                });
                
                block_id += 1;
                current_block_instructions.clear();
            }

            // Start new block if needed
            if current_block_instructions.is_empty() {
                block_start_addr = instruction.address;
            }

            current_block_instructions.push(instruction.clone());

            // End block if this is a control flow instruction
            match instruction.flow_control {
                FlowControl::Return | FlowControl::Jump(_) | FlowControl::Halt => {
                    let end_addr = instruction.address + instruction.size as u64;
                    let block_type = self.determine_block_type(&current_block_instructions);
                    
                    basic_blocks.push(BasicBlock {
                        id: block_id,
                        start_address: block_start_addr,
                        end_address: end_addr,
                        instruction_count: current_block_instructions.len(),
                        instructions: current_block_instructions.clone(),
                        successors: Vec::new(),
                        predecessors: Vec::new(),
                        block_type,
                    });
                    
                    block_id += 1;
                    current_block_instructions.clear();
                }
                _ => {}
            }
        }

        // Handle any remaining instructions
        if !current_block_instructions.is_empty() {
            let end_addr = current_block_instructions.last().unwrap().address + 
                          current_block_instructions.last().unwrap().size as u64;
            let block_type = self.determine_block_type(&current_block_instructions);
            
            basic_blocks.push(BasicBlock {
                id: block_id,
                start_address: block_start_addr,
                end_address: end_addr,
                instruction_count: current_block_instructions.len(),
                instructions: current_block_instructions,
                successors: Vec::new(),
                predecessors: Vec::new(),
                block_type,
            });
        }

        basic_blocks
    }

    fn determine_block_type(&self, instructions: &[Instruction]) -> BlockType {
        if let Some(last_insn) = instructions.last() {
            match &last_insn.flow_control {
                FlowControl::Return => BlockType::Return,
                FlowControl::Call(_) => BlockType::Call,
                FlowControl::Branch(_) => BlockType::Conditional,
                _ => BlockType::Normal,
            }
        } else {
            BlockType::Normal
        }
    }

    fn build_control_flow_edges(&self, basic_blocks: &[BasicBlock]) -> Vec<CfgEdge> {
        let mut edges = Vec::new();
        
        // Create address to block ID mapping
        let mut addr_to_block: HashMap<u64, usize> = HashMap::new();
        for block in basic_blocks {
            addr_to_block.insert(block.start_address, block.id);
        }

        for block in basic_blocks {
            if let Some(last_insn) = block.instructions.last() {
                match &last_insn.flow_control {
                    FlowControl::Jump(target) => {
                        if let Some(&target_block) = addr_to_block.get(target) {
                            edges.push(CfgEdge {
                                from_block: block.id,
                                to_block: target_block,
                                edge_type: EdgeType::Jump,
                            });
                        }
                    }
                    FlowControl::Branch(target) => {
                        // Conditional branch has two edges: taken and not taken
                        if let Some(&target_block) = addr_to_block.get(target) {
                            edges.push(CfgEdge {
                                from_block: block.id,
                                to_block: target_block,
                                edge_type: EdgeType::Branch,
                            });
                        }
                        
                        // Fall-through edge to next block
                        if let Some(next_block) = basic_blocks.get(block.id + 1) {
                            edges.push(CfgEdge {
                                from_block: block.id,
                                to_block: next_block.id,
                                edge_type: EdgeType::Fall,
                            });
                        }
                    }
                    FlowControl::Call(target) => {
                        if let Some(&target_block) = addr_to_block.get(target) {
                            edges.push(CfgEdge {
                                from_block: block.id,
                                to_block: target_block,
                                edge_type: EdgeType::Call,
                            });
                        }
                        
                        // Fall-through after call
                        if let Some(next_block) = basic_blocks.get(block.id + 1) {
                            edges.push(CfgEdge {
                                from_block: block.id,
                                to_block: next_block.id,
                                edge_type: EdgeType::Fall,
                            });
                        }
                    }
                    FlowControl::Fall => {
                        // Normal fall-through to next block
                        if let Some(next_block) = basic_blocks.get(block.id + 1) {
                            edges.push(CfgEdge {
                                from_block: block.id,
                                to_block: next_block.id,
                                edge_type: EdgeType::Fall,
                            });
                        }
                    }
                    FlowControl::Return | FlowControl::Halt => {
                        // No outgoing edges
                    }
                    FlowControl::Indirect => {
                        // For indirect jumps/calls, we can't determine the target statically
                        // In a more sophisticated analysis, we might try to resolve these
                    }
                }
            }
        }

        edges
    }

    fn detect_loops(&self, _basic_blocks: &[BasicBlock], edges: &[CfgEdge]) -> Vec<Loop> {
        let mut loops = Vec::new();
        
        // Simple back-edge detection for natural loops
        for edge in edges {
            if edge.to_block <= edge.from_block {
                // Potential back edge - suggests a loop
                loops.push(Loop {
                    header_block: edge.to_block,
                    body_blocks: vec![edge.from_block],
                    exit_blocks: Vec::new(),
                    loop_type: LoopType::Natural,
                    nesting_level: 1,
                });
            }
        }

        loops
    }

    fn calculate_complexity_metrics(&self, basic_blocks: &[BasicBlock], edges: &[CfgEdge], loops: &[Loop]) -> ControlFlowMetrics {
        // Cyclomatic complexity: V(G) = E - N + 2P
        // Where E = edges, N = nodes (basic blocks), P = connected components (assume 1)
        let cyclomatic_complexity = if basic_blocks.len() <= 1 {
            1
        } else {
            (edges.len() as i32 - basic_blocks.len() as i32 + 2).max(1) as u32
        };

        // Simple cognitive complexity based on control structures
        let cognitive_complexity = self.calculate_cognitive_complexity(basic_blocks);
        
        // Nesting depth
        let nesting_depth = self.calculate_nesting_depth(basic_blocks);
        
        // Find unreachable blocks
        let unreachable_blocks = self.find_unreachable_blocks(basic_blocks, edges);

        ControlFlowMetrics {
            cyclomatic_complexity,
            cognitive_complexity,
            nesting_depth,
            basic_block_count: basic_blocks.len(),
            edge_count: edges.len(),
            loop_count: loops.len(),
            unreachable_blocks,
        }
    }

    fn calculate_cognitive_complexity(&self, basic_blocks: &[BasicBlock]) -> u32 {
        let mut complexity = 0;
        
        for block in basic_blocks {
            match block.block_type {
                BlockType::Conditional => complexity += 1,
                BlockType::LoopHeader | BlockType::LoopBody => complexity += 2,
                _ => {}
            }
        }
        
        complexity
    }

    fn calculate_nesting_depth(&self, basic_blocks: &[BasicBlock]) -> u32 {
        // Simplified nesting depth calculation
        let mut max_depth: u32 = 0;
        let mut current_depth: i32 = 0;
        
        for block in basic_blocks {
            match block.block_type {
                BlockType::Conditional => {
                    current_depth += 1;
                    max_depth = max_depth.max(current_depth as u32);
                }
                BlockType::Return | BlockType::Exit => {
                    current_depth = current_depth.saturating_sub(1);
                }
                _ => {}
            }
        }
        
        max_depth
    }

    fn find_unreachable_blocks(&self, basic_blocks: &[BasicBlock], edges: &[CfgEdge]) -> Vec<usize> {
        let mut reachable = HashSet::new();
        let mut queue = VecDeque::new();
        
        // Start from entry block (block 0)
        if !basic_blocks.is_empty() {
            queue.push_back(0);
            reachable.insert(0);
        }
        
        // BFS to find all reachable blocks
        while let Some(block_id) = queue.pop_front() {
            for edge in edges {
                if edge.from_block == block_id && !reachable.contains(&edge.to_block) {
                    reachable.insert(edge.to_block);
                    queue.push_back(edge.to_block);
                }
            }
        }
        
        // Find unreachable blocks
        basic_blocks
            .iter()
            .filter(|block| !reachable.contains(&block.id))
            .map(|block| block.id)
            .collect()
    }

    fn find_exit_blocks(&self, basic_blocks: &[BasicBlock]) -> Vec<usize> {
        basic_blocks
            .iter()
            .filter(|block| matches!(block.block_type, BlockType::Return | BlockType::Exit))
            .map(|block| block.id)
            .collect()
    }
}

pub fn analyze_control_flow(path: &Path, symbol_table: &SymbolTable) -> Result<ControlFlowAnalysis> {
    // Read the binary file
    let mut file = File::open(path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    // Parse the binary to get the text section info
    let obj = Object::parse(&buffer)?;
    
    match obj {
        Object::Elf(elf) => {
            // Find the .text section
            for (i, section) in elf.section_headers.iter().enumerate() {
                if let Some(name) = elf.shdr_strtab.get_at(section.sh_name) {
                    if name == ".text" {
                        let analyzer = ControlFlowAnalyzer::new_x86_64()?;
                        return analyzer.analyze_functions(
                            &buffer,
                            symbol_table,
                            section.sh_offset,
                            section.sh_addr,
                        );
                    }
                } else {
                    // For debugging: check section 16 specifically (.text section from readelf)
                    if i == 16 {
                        let analyzer = ControlFlowAnalyzer::new_x86_64()?;
                        return analyzer.analyze_functions(
                            &buffer,
                            symbol_table,
                            section.sh_offset,
                            section.sh_addr,
                        );
                    }
                }
            }
            Err(anyhow!("No .text section found"))
        }
        _ => Err(anyhow!("Only ELF binaries are currently supported for CFG analysis")),
    }
}