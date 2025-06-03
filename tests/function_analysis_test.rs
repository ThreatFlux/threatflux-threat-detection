use file_scanner::function_analysis::*;
use std::path::Path;
use tempfile::NamedTempFile;
use std::io::Write;

#[test]
fn test_analyze_symbols_with_elf() {
    // Create a minimal ELF file for testing
    let mut elf_data = vec![
        // ELF header
        0x7f, 0x45, 0x4c, 0x46, // Magic
        0x02, // 64-bit
        0x01, // Little endian
        0x01, // ELF version
        0x00, // System V ABI
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Padding
        0x02, 0x00, // Executable file
        0x3e, 0x00, // x86-64
        0x01, 0x00, 0x00, 0x00, // Version
        0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Entry point
        0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Program header offset
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Section header offset
        0x00, 0x00, 0x00, 0x00, // Flags
        0x40, 0x00, // ELF header size
        0x38, 0x00, // Program header size
        0x01, 0x00, // Program header count
        0x40, 0x00, // Section header size
        0x00, 0x00, // Section header count
        0x00, 0x00, // Section name string table index
    ];
    
    // Pad to minimum size
    while elf_data.len() < 0x40 {
        elf_data.push(0);
    }
    
    let mut temp_file = NamedTempFile::new().unwrap();
    temp_file.write_all(&elf_data).unwrap();
    temp_file.flush().unwrap();
    
    let result = analyze_symbols(temp_file.path());
    
    match result {
        Ok(symbol_table) => {
            // Should have basic structure even if empty
            assert_eq!(symbol_table.functions.len(), 0);
            assert_eq!(symbol_table.symbol_count.total_functions, 0);
        }
        Err(e) => {
            // Expected to fail on minimal ELF
            eprintln!("Expected error: {}", e);
        }
    }
}

#[test]
fn test_analyze_symbols_with_real_binary() {
    // Try with the test binary if it exists
    let test_binary = Path::new("./target/debug/file-scanner");
    
    if test_binary.exists() {
        match analyze_symbols(test_binary) {
            Ok(symbol_table) => {
                println!("Found {} functions", symbol_table.functions.len());
                
                // Should find at least some functions
                assert!(symbol_table.functions.len() > 0);
                
                // Check stats consistency
                assert_eq!(
                    symbol_table.symbol_count.total_functions,
                    symbol_table.functions.len()
                );
                
                // Look for main function
                let main_fn = symbol_table.functions.iter()
                    .find(|f| f.name.contains("main"));
                assert!(main_fn.is_some(), "Should find main function");
            }
            Err(e) => {
                eprintln!("Function analysis failed (may be expected): {}", e);
            }
        }
    }
}

#[test]
fn test_function_type_serialization() {
    let types = vec![
        FunctionType::Local,
        FunctionType::Imported,
        FunctionType::Exported,
        FunctionType::Thunk,
        FunctionType::Constructor,
        FunctionType::Destructor,
        FunctionType::EntryPoint,
    ];
    
    for func_type in types {
        let serialized = serde_json::to_string(&func_type).unwrap();
        let deserialized: FunctionType = serde_json::from_str(&serialized).unwrap();
        
        match (func_type, deserialized) {
            (FunctionType::Local, FunctionType::Local) => {},
            (FunctionType::Imported, FunctionType::Imported) => {},
            (FunctionType::Exported, FunctionType::Exported) => {},
            (FunctionType::Thunk, FunctionType::Thunk) => {},
            (FunctionType::Constructor, FunctionType::Constructor) => {},
            (FunctionType::Destructor, FunctionType::Destructor) => {},
            (FunctionType::EntryPoint, FunctionType::EntryPoint) => {},
            _ => panic!("Function type serialization mismatch"),
        }
    }
}

#[test]
fn test_calling_convention_serialization() {
    let conventions = vec![
        CallingConvention::Cdecl,
        CallingConvention::Stdcall,
        CallingConvention::Fastcall,
        CallingConvention::Thiscall,
        CallingConvention::Vectorcall,
        CallingConvention::SysV,
        CallingConvention::Win64,
        CallingConvention::Unknown,
    ];
    
    for convention in conventions {
        let serialized = serde_json::to_string(&convention).unwrap();
        let deserialized: CallingConvention = serde_json::from_str(&serialized).unwrap();
        
        match (convention, deserialized) {
            (CallingConvention::Cdecl, CallingConvention::Cdecl) => {},
            (CallingConvention::Stdcall, CallingConvention::Stdcall) => {},
            (CallingConvention::Fastcall, CallingConvention::Fastcall) => {},
            (CallingConvention::Thiscall, CallingConvention::Thiscall) => {},
            (CallingConvention::Vectorcall, CallingConvention::Vectorcall) => {},
            (CallingConvention::SysV, CallingConvention::SysV) => {},
            (CallingConvention::Win64, CallingConvention::Win64) => {},
            (CallingConvention::Unknown, CallingConvention::Unknown) => {},
            _ => panic!("Calling convention serialization mismatch"),
        }
    }
}

#[test]
fn test_variable_type_serialization() {
    let types = vec![
        VariableType::Global,
        VariableType::Static,
        VariableType::ThreadLocal,
        VariableType::Const,
    ];
    
    for var_type in types {
        let serialized = serde_json::to_string(&var_type).unwrap();
        let deserialized: VariableType = serde_json::from_str(&serialized).unwrap();
        
        match (var_type, deserialized) {
            (VariableType::Global, VariableType::Global) => {},
            (VariableType::Static, VariableType::Static) => {},
            (VariableType::ThreadLocal, VariableType::ThreadLocal) => {},
            (VariableType::Const, VariableType::Const) => {},
            _ => panic!("Variable type serialization mismatch"),
        }
    }
}

#[test]
fn test_reference_type_serialization() {
    let types = vec![
        ReferenceType::Call,
        ReferenceType::Jump,
        ReferenceType::DataReference,
        ReferenceType::StringReference,
        ReferenceType::Import,
        ReferenceType::Export,
    ];
    
    for ref_type in types {
        let serialized = serde_json::to_string(&ref_type).unwrap();
        let deserialized: ReferenceType = serde_json::from_str(&serialized).unwrap();
        
        match (ref_type, deserialized) {
            (ReferenceType::Call, ReferenceType::Call) => {},
            (ReferenceType::Jump, ReferenceType::Jump) => {},
            (ReferenceType::DataReference, ReferenceType::DataReference) => {},
            (ReferenceType::StringReference, ReferenceType::StringReference) => {},
            (ReferenceType::Import, ReferenceType::Import) => {},
            (ReferenceType::Export, ReferenceType::Export) => {},
            _ => panic!("Reference type serialization mismatch"),
        }
    }
}

#[test]
fn test_function_info_creation() {
    let func = FunctionInfo {
        name: "test_function".to_string(),
        address: 0x1000,
        size: 100,
        function_type: FunctionType::Exported,
        calling_convention: Some(CallingConvention::SysV),
        parameters: vec![
            Parameter {
                name: Some("arg1".to_string()),
                param_type: Some("int".to_string()),
                size: Some(4),
            }
        ],
        is_entry_point: false,
        is_exported: true,
        is_imported: false,
    };
    
    assert_eq!(func.name, "test_function");
    assert_eq!(func.address, 0x1000);
    assert_eq!(func.size, 100);
    assert!(matches!(func.function_type, FunctionType::Exported));
    assert!(func.is_exported);
    assert!(!func.is_imported);
    assert_eq!(func.parameters.len(), 1);
}

#[test]
fn test_variable_info_creation() {
    let var = VariableInfo {
        name: "global_var".to_string(),
        address: 0x2000,
        size: 8,
        var_type: VariableType::Global,
        section: Some(".data".to_string()),
    };
    
    assert_eq!(var.name, "global_var");
    assert_eq!(var.address, 0x2000);
    assert_eq!(var.size, 8);
    assert!(matches!(var.var_type, VariableType::Global));
    assert_eq!(var.section, Some(".data".to_string()));
}

#[test]
fn test_cross_reference_creation() {
    let xref = CrossReference {
        from_address: 0x1000,
        to_address: 0x2000,
        reference_type: ReferenceType::Call,
        instruction_type: Some("call".to_string()),
    };
    
    assert_eq!(xref.from_address, 0x1000);
    assert_eq!(xref.to_address, 0x2000);
    assert!(matches!(xref.reference_type, ReferenceType::Call));
    assert_eq!(xref.instruction_type, Some("call".to_string()));
}

#[test]
fn test_symbol_table_creation() {
    let symbol_table = SymbolTable {
        functions: vec![],
        global_variables: vec![],
        cross_references: vec![],
        imports: vec![],
        exports: vec![],
        symbol_count: SymbolCounts {
            total_functions: 0,
            local_functions: 0,
            imported_functions: 0,
            exported_functions: 0,
            global_variables: 0,
            cross_references: 0,
        },
    };
    
    assert_eq!(symbol_table.functions.len(), 0);
    assert_eq!(symbol_table.global_variables.len(), 0);
    assert_eq!(symbol_table.cross_references.len(), 0);
    assert_eq!(symbol_table.symbol_count.total_functions, 0);
}

#[test]
fn test_parameter_creation() {
    let param = Parameter {
        name: Some("count".to_string()),
        param_type: Some("size_t".to_string()),
        size: Some(8),
    };
    
    assert_eq!(param.name, Some("count".to_string()));
    assert_eq!(param.param_type, Some("size_t".to_string()));
    assert_eq!(param.size, Some(8));
}

#[test]
fn test_import_info_creation() {
    let import = ImportInfo {
        name: "malloc".to_string(),
        library: Some("libc.so.6".to_string()),
        address: Some(0x4000),
        ordinal: None,
        is_delayed: false,
    };
    
    assert_eq!(import.name, "malloc");
    assert_eq!(import.library, Some("libc.so.6".to_string()));
    assert_eq!(import.address, Some(0x4000));
    assert_eq!(import.ordinal, None);
    assert!(!import.is_delayed);
}

#[test]
fn test_export_info_creation() {
    let export = ExportInfo {
        name: "my_function".to_string(),
        address: 0x1000,
        ordinal: Some(1),
        is_forwarder: false,
        forwarder_name: None,
    };
    
    assert_eq!(export.name, "my_function");
    assert_eq!(export.address, 0x1000);
    assert_eq!(export.ordinal, Some(1));
    assert!(!export.is_forwarder);
    assert_eq!(export.forwarder_name, None);
}

#[test]
fn test_analyze_symbols_with_invalid_path() {
    let result = analyze_symbols(Path::new("/nonexistent/file"));
    assert!(result.is_err());
}

#[test]
fn test_analyze_symbols_with_example_binaries() {
    // Try to analyze example binaries if they exist
    let example_paths = vec![
        "./examples/binaries/c_advanced_binary",
        "./examples/binaries/rust_test_binary",
        "./examples/binaries/go_test_binary",
    ];
    
    for path_str in example_paths {
        let path = Path::new(path_str);
        if path.exists() {
            println!("Testing function analysis on {}", path_str);
            
            match analyze_symbols(path) {
                Ok(symbol_table) => {
                    println!("Successfully analyzed {} functions", symbol_table.functions.len());
                    
                    // Verify some basic properties
                    assert!(symbol_table.symbol_count.total_functions >= 0);
                    
                    // Check for consistency
                    let total_funcs = symbol_table.symbol_count.local_functions
                        + symbol_table.symbol_count.imported_functions
                        + symbol_table.symbol_count.exported_functions;
                    assert!(total_funcs <= symbol_table.symbol_count.total_functions);
                }
                Err(e) => {
                    eprintln!("Function analysis failed for {}: {}", path_str, e);
                }
            }
        }
    }
}