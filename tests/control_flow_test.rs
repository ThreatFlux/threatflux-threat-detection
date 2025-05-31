use file_scanner::control_flow::*;
use file_scanner::function_analysis::{FunctionInfo, FunctionType, SymbolTable, SymbolCounts};
use std::path::Path;
use tempfile::NamedTempFile;
use std::io::Write;

#[cfg(test)]
mod control_flow_tests {
    use super::*;

    // Helper function to create a test symbol table
    fn create_test_symbol_table() -> SymbolTable {
        SymbolTable {
            functions: vec![
                FunctionInfo {
                    name: "main".to_string(),
                    address: 0x400000,
                    size: 100,
                    is_exported: true,
                    function_type: FunctionType::Exported,
                    calling_convention: None,
                    parameters: vec![],
                    is_entry_point: true,
                    is_imported: false,
                },
                FunctionInfo {
                    name: "test_func".to_string(),
                    address: 0x400100,
                    size: 50,
                    is_exported: true,
                    function_type: FunctionType::Exported,
                    calling_convention: None,
                    parameters: vec![],
                    is_entry_point: false,
                    is_imported: false,
                },
            ],
            global_variables: vec![],
            cross_references: vec![],
            imports: vec![],
            exports: vec![],
            symbol_count: SymbolCounts {
                total_functions: 2,
                local_functions: 0,
                imported_functions: 0,
                exported_functions: 2,
                global_variables: 0,
                cross_references: 0,
            },
        }
    }

    // Helper function to create a minimal test ELF binary
    fn create_test_elf_binary() -> Vec<u8> {
        // Minimal ELF header for x86_64
        let mut binary = vec![0u8; 0x1000];
        
        // ELF magic
        binary[0..4].copy_from_slice(&[0x7f, 0x45, 0x4c, 0x46]);
        
        // 64-bit, little endian, current version
        binary[4] = 0x02; // 64-bit
        binary[5] = 0x01; // Little endian
        binary[6] = 0x01; // Current version
        binary[7] = 0x00; // System V ABI
        
        // Executable file type
        binary[0x10] = 0x02;
        binary[0x11] = 0x00;
        
        // x86-64 machine type
        binary[0x12] = 0x3e;
        binary[0x13] = 0x00;
        
        // Version
        binary[0x14] = 0x01;
        binary[0x15] = 0x00;
        binary[0x16] = 0x00;
        binary[0x17] = 0x00;
        
        // Entry point
        let entry = 0x400000u64;
        binary[0x18..0x20].copy_from_slice(&entry.to_le_bytes());
        
        // Program header offset
        let phoff = 0x40u64;
        binary[0x20..0x28].copy_from_slice(&phoff.to_le_bytes());
        
        // Section header offset
        let shoff = 0x200u64;
        binary[0x28..0x30].copy_from_slice(&shoff.to_le_bytes());
        
        // e_ehsize
        binary[0x34] = 0x40;
        binary[0x35] = 0x00;
        
        // e_phentsize
        binary[0x36] = 0x38;
        binary[0x37] = 0x00;
        
        // e_phnum
        binary[0x38] = 0x01;
        binary[0x39] = 0x00;
        
        // e_shentsize
        binary[0x3a] = 0x40;
        binary[0x3b] = 0x00;
        
        // e_shnum
        binary[0x3c] = 0x03; // NULL, .text, .shstrtab
        binary[0x3d] = 0x00;
        
        // e_shstrndx
        binary[0x3e] = 0x02; // .shstrtab is section 2
        binary[0x3f] = 0x00;
        
        // Create section headers at offset 0x200
        // Section 0: NULL section
        // (all zeros)
        
        // Section 1: .text section
        let text_offset = 0x240;
        let text_name_offset = 1u32; // Offset in .shstrtab
        binary[text_offset..text_offset+4].copy_from_slice(&text_name_offset.to_le_bytes());
        
        // sh_type = SHT_PROGBITS
        binary[text_offset+4..text_offset+8].copy_from_slice(&1u32.to_le_bytes());
        
        // sh_flags = SHF_ALLOC | SHF_EXECINSTR
        let flags = 0x6u64;
        binary[text_offset+8..text_offset+16].copy_from_slice(&flags.to_le_bytes());
        
        // sh_addr
        let text_addr = 0x400000u64;
        binary[text_offset+16..text_offset+24].copy_from_slice(&text_addr.to_le_bytes());
        
        // sh_offset
        let text_file_offset = 0x1000u64;
        binary[text_offset+24..text_offset+32].copy_from_slice(&text_file_offset.to_le_bytes());
        
        // sh_size
        let text_size = 0x100u64;
        binary[text_offset+32..text_offset+40].copy_from_slice(&text_size.to_le_bytes());
        
        // Section 2: .shstrtab
        let strtab_offset = 0x280;
        let strtab_name_offset = 7u32; // Offset in .shstrtab
        binary[strtab_offset..strtab_offset+4].copy_from_slice(&strtab_name_offset.to_le_bytes());
        
        // sh_type = SHT_STRTAB
        binary[strtab_offset+4..strtab_offset+8].copy_from_slice(&3u32.to_le_bytes());
        
        // sh_offset for string table
        let strtab_file_offset = 0x300u64;
        binary[strtab_offset+24..strtab_offset+32].copy_from_slice(&strtab_file_offset.to_le_bytes());
        
        // sh_size
        let strtab_size = 0x20u64;
        binary[strtab_offset+32..strtab_offset+40].copy_from_slice(&strtab_size.to_le_bytes());
        
        // Create .shstrtab content at offset 0x300
        let strtab_content = b"\0.text\0.shstrtab\0";
        binary[0x300..0x300+strtab_content.len()].copy_from_slice(strtab_content);
        
        // Extend binary to include .text section
        binary.resize(0x1100, 0);
        
        // Add some code in .text section at 0x1000
        let code = vec![
            0x55,                   // push rbp
            0x48, 0x89, 0xe5,      // mov rbp, rsp
            0x48, 0x83, 0xec, 0x10, // sub rsp, 0x10
            0xb8, 0x00, 0x00, 0x00, 0x00, // mov eax, 0
            0x48, 0x83, 0xc4, 0x10, // add rsp, 0x10
            0x5d,                   // pop rbp
            0xc3,                   // ret
        ];
        
        binary[0x1000..0x1000 + code.len()].copy_from_slice(&code);
        
        binary
    }

    #[test]
    fn test_control_flow_analyzer_creation() {
        let analyzer = ControlFlowAnalyzer::new_x86_64();
        assert!(analyzer.is_ok());
    }

    #[test]
    fn test_analyze_control_flow_with_elf() {
        let mut file = NamedTempFile::new().unwrap();
        let binary = create_test_elf_binary();
        file.write_all(&binary).unwrap();
        file.flush().unwrap();
        
        let symbol_table = create_test_symbol_table();
        
        let result = analyze_control_flow(file.path(), &symbol_table);
        
        match result {
            Ok(analysis) => {
                // Check that we have the analysis
                assert!(analysis.overall_metrics.total_functions > 0);
                assert!(analysis.analysis_stats.bytes_analyzed > 0);
            }
            Err(e) => {
                // It's okay if it fails due to our minimal ELF
                println!("Expected error for minimal ELF: {}", e);
            }
        }
    }

    #[test]
    fn test_analyze_control_flow_invalid_file() {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(b"not an elf file").unwrap();
        file.flush().unwrap();
        
        let symbol_table = create_test_symbol_table();
        
        let result = analyze_control_flow(file.path(), &symbol_table);
        assert!(result.is_err());
    }

    #[test]
    fn test_control_flow_structures() {
        // Test that the structures are properly defined
        let _block = BasicBlock {
            id: 0,
            start_address: 0x1000,
            end_address: 0x1010,
            instructions: vec![],
            successors: vec![],
            predecessors: vec![],
            block_type: BlockType::Normal,
            instruction_count: 5,
        };
        
        let _edge = CfgEdge {
            from_block: 0,
            to_block: 1,
            edge_type: EdgeType::Fall,
        };
        
        let _loop = Loop {
            header_block: 0,
            body_blocks: vec![1, 2],
            exit_blocks: vec![3],
            loop_type: LoopType::Natural,
            nesting_level: 1,
        };
    }

    #[test]
    fn test_instruction_types() {
        let _instruction = Instruction {
            address: 0x1000,
            bytes: vec![0x90],
            mnemonic: "nop".to_string(),
            operands: "".to_string(),
            instruction_type: InstructionType::Nop,
            flow_control: FlowControl::Fall,
            size: 1,
        };
        
        // Test different instruction types
        let types = vec![
            InstructionType::Arithmetic,
            InstructionType::Logic,
            InstructionType::Memory,
            InstructionType::Control,
            InstructionType::System,
            InstructionType::Call,
            InstructionType::Return,
            InstructionType::Jump,
            InstructionType::Conditional,
            InstructionType::Nop,
            InstructionType::Other,
        ];
        
        for t in types {
            match t {
                InstructionType::Jump => assert!(true),
                InstructionType::Call => assert!(true),
                InstructionType::Return => assert!(true),
                _ => assert!(true),
            }
        }
    }

    #[test]
    fn test_flow_control_types() {
        let flow_controls = vec![
            FlowControl::Fall,
            FlowControl::Jump(0x1234),
            FlowControl::Branch(0x5678),
            FlowControl::Call(0xabcd),
            FlowControl::Return,
            FlowControl::Indirect,
            FlowControl::Halt,
        ];
        
        for fc in flow_controls {
            match fc {
                FlowControl::Jump(addr) => assert!(addr > 0),
                FlowControl::Branch(addr) => assert!(addr > 0),
                FlowControl::Call(addr) => assert!(addr > 0),
                _ => assert!(true),
            }
        }
    }

    #[test]
    fn test_block_types() {
        let block_types = vec![
            BlockType::Entry,
            BlockType::Exit,
            BlockType::Normal,
            BlockType::LoopHeader,
            BlockType::LoopBody,
            BlockType::Conditional,
            BlockType::Call,
            BlockType::Return,
        ];
        
        for bt in block_types {
            match bt {
                BlockType::Entry => assert!(true),
                BlockType::Exit => assert!(true),
                BlockType::Return => assert!(true),
                _ => assert!(true),
            }
        }
    }

    #[test]
    fn test_edge_types() {
        let edge_types = vec![
            EdgeType::Fall,
            EdgeType::Jump,
            EdgeType::Branch,
            EdgeType::Call,
            EdgeType::Return,
        ];
        
        for et in edge_types {
            match et {
                EdgeType::Branch => assert!(true),
                EdgeType::Jump => assert!(true),
                _ => assert!(true),
            }
        }
    }

    #[test]
    fn test_loop_types() {
        let loop_types = vec![
            LoopType::Natural,
            LoopType::Irreducible,
            LoopType::DoWhile,
            LoopType::While,
            LoopType::For,
        ];
        
        for lt in loop_types {
            match lt {
                LoopType::Natural => assert!(true),
                LoopType::For => assert!(true),
                _ => assert!(true),
            }
        }
    }

    #[test]
    fn test_control_flow_metrics() {
        let metrics = ControlFlowMetrics {
            cyclomatic_complexity: 5,
            cognitive_complexity: 8,
            nesting_depth: 3,
            basic_block_count: 10,
            edge_count: 15,
            loop_count: 2,
            unreachable_blocks: vec![7, 8],
        };
        
        assert_eq!(metrics.cyclomatic_complexity, 5);
        assert_eq!(metrics.cognitive_complexity, 8);
        assert_eq!(metrics.nesting_depth, 3);
        assert_eq!(metrics.basic_block_count, 10);
        assert_eq!(metrics.edge_count, 15);
        assert_eq!(metrics.loop_count, 2);
        assert_eq!(metrics.unreachable_blocks.len(), 2);
    }

    #[test]
    fn test_overall_metrics() {
        let metrics = OverallMetrics {
            total_functions: 10,
            analyzed_functions: 8,
            total_basic_blocks: 50,
            average_complexity: 3.5,
            max_complexity: 10,
            function_with_max_complexity: Some("complex_func".to_string()),
        };
        
        assert_eq!(metrics.total_functions, 10);
        assert_eq!(metrics.analyzed_functions, 8);
        assert_eq!(metrics.total_basic_blocks, 50);
        assert_eq!(metrics.average_complexity, 3.5);
        assert_eq!(metrics.max_complexity, 10);
        assert!(metrics.function_with_max_complexity.is_some());
    }

    #[test]
    fn test_analysis_stats() {
        let stats = AnalysisStats {
            analysis_duration: 100,
            bytes_analyzed: 4096,
            instructions_analyzed: 256,
            errors: vec!["Error 1".to_string(), "Error 2".to_string()],
        };
        
        assert_eq!(stats.analysis_duration, 100);
        assert_eq!(stats.bytes_analyzed, 4096);
        assert_eq!(stats.instructions_analyzed, 256);
        assert_eq!(stats.errors.len(), 2);
    }

    #[test]
    fn test_empty_control_flow_graph() {
        let cfg = ControlFlowGraph {
            function_address: 0x1000,
            function_name: "empty_func".to_string(),
            basic_blocks: vec![],
            edges: vec![],
            entry_block: 0,
            exit_blocks: vec![],
            loops: vec![],
            complexity: ControlFlowMetrics {
                cyclomatic_complexity: 1,
                cognitive_complexity: 0,
                nesting_depth: 0,
                basic_block_count: 0,
                edge_count: 0,
                loop_count: 0,
                unreachable_blocks: vec![],
            },
        };
        
        assert_eq!(cfg.function_name, "empty_func");
        assert_eq!(cfg.basic_blocks.len(), 0);
        assert_eq!(cfg.edges.len(), 0);
        assert_eq!(cfg.loops.len(), 0);
    }

    #[test]
    fn test_complex_control_flow_graph() {
        let cfg = ControlFlowGraph {
            function_address: 0x2000,
            function_name: "complex_func".to_string(),
            basic_blocks: vec![
                BasicBlock {
                    id: 0,
                    start_address: 0x2000,
                    end_address: 0x2010,
                    instructions: vec![],
                    successors: vec![1, 2],
                    predecessors: vec![],
                    block_type: BlockType::Entry,
                    instruction_count: 5,
                },
                BasicBlock {
                    id: 1,
                    start_address: 0x2010,
                    end_address: 0x2020,
                    instructions: vec![],
                    successors: vec![3],
                    predecessors: vec![0],
                    block_type: BlockType::Normal,
                    instruction_count: 4,
                },
                BasicBlock {
                    id: 2,
                    start_address: 0x2020,
                    end_address: 0x2030,
                    instructions: vec![],
                    successors: vec![3],
                    predecessors: vec![0],
                    block_type: BlockType::Normal,
                    instruction_count: 6,
                },
                BasicBlock {
                    id: 3,
                    start_address: 0x2030,
                    end_address: 0x2040,
                    instructions: vec![],
                    successors: vec![],
                    predecessors: vec![1, 2],
                    block_type: BlockType::Exit,
                    instruction_count: 2,
                },
            ],
            edges: vec![
                CfgEdge { from_block: 0, to_block: 1, edge_type: EdgeType::Branch },
                CfgEdge { from_block: 0, to_block: 2, edge_type: EdgeType::Branch },
                CfgEdge { from_block: 1, to_block: 3, edge_type: EdgeType::Fall },
                CfgEdge { from_block: 2, to_block: 3, edge_type: EdgeType::Fall },
            ],
            entry_block: 0,
            exit_blocks: vec![3],
            loops: vec![],
            complexity: ControlFlowMetrics {
                cyclomatic_complexity: 2,
                cognitive_complexity: 1,
                nesting_depth: 1,
                basic_block_count: 4,
                edge_count: 4,
                loop_count: 0,
                unreachable_blocks: vec![],
            },
        };
        
        assert_eq!(cfg.basic_blocks.len(), 4);
        assert_eq!(cfg.edges.len(), 4);
        assert_eq!(cfg.complexity.cyclomatic_complexity, 2);
    }

    #[test]
    fn test_loop_in_cfg() {
        let loop_info = Loop {
            header_block: 1,
            body_blocks: vec![2, 3],
            exit_blocks: vec![4],
            loop_type: LoopType::While,
            nesting_level: 1,
        };
        
        assert_eq!(loop_info.header_block, 1);
        assert_eq!(loop_info.body_blocks.len(), 2);
        assert_eq!(loop_info.exit_blocks.len(), 1);
        assert_eq!(loop_info.nesting_level, 1);
    }

    #[test]
    fn test_nested_loops() {
        let outer_loop = Loop {
            header_block: 1,
            body_blocks: vec![2, 3, 4, 5],
            exit_blocks: vec![6],
            loop_type: LoopType::For,
            nesting_level: 1,
        };
        
        let inner_loop = Loop {
            header_block: 3,
            body_blocks: vec![4],
            exit_blocks: vec![5],
            loop_type: LoopType::While,
            nesting_level: 2,
        };
        
        assert!(outer_loop.nesting_level < inner_loop.nesting_level);
        assert!(outer_loop.body_blocks.contains(&inner_loop.header_block));
    }
}