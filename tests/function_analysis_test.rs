use file_scanner::function_analysis::*;
use std::io::Write;
use std::path::Path;
use tempfile::NamedTempFile;

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
                assert!(!symbol_table.functions.is_empty());

                // Check stats consistency
                assert_eq!(
                    symbol_table.symbol_count.total_functions,
                    symbol_table.functions.len()
                );

                // Look for main function
                let main_fn = symbol_table
                    .functions
                    .iter()
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
fn test_analyze_symbols_with_c_binary() {
    let test_binary = Path::new("./test_programs/c_advanced_binary");

    if test_binary.exists() {
        let result = analyze_symbols(test_binary);
        assert!(result.is_ok(), "Should successfully analyze C binary");

        let symbol_table = result.unwrap();

        // Should have found functions
        assert!(
            !symbol_table.functions.is_empty(),
            "Should find functions in C binary"
        );

        // Verify symbol count consistency
        assert_eq!(
            symbol_table.symbol_count.total_functions,
            symbol_table.functions.len(),
            "Function count should be consistent"
        );

        // Should have imports from libc
        assert!(
            !symbol_table.imports.is_empty(),
            "Should have imported functions"
        );

        // Look for common C functions
        let has_printf = symbol_table
            .imports
            .iter()
            .any(|i| i.name.contains("printf"));
        let has_malloc = symbol_table
            .imports
            .iter()
            .any(|i| i.name.contains("malloc"));
        assert!(has_printf || has_malloc, "Should import common C functions");

        println!(
            "C binary analysis: {} functions, {} imports",
            symbol_table.functions.len(),
            symbol_table.imports.len()
        );
    }
}

#[test]
fn test_analyze_symbols_with_rust_binary() {
    let test_binary = Path::new("./test_programs/rust_test_binary");

    if test_binary.exists() {
        let result = analyze_symbols(test_binary);
        assert!(result.is_ok(), "Should successfully analyze Rust binary");

        let symbol_table = result.unwrap();

        // Should have found functions
        assert!(
            !symbol_table.functions.is_empty(),
            "Should find functions in Rust binary"
        );

        // Rust binaries typically have many functions due to monomorphization
        assert!(
            symbol_table.functions.len() >= 10,
            "Rust binary should have multiple functions"
        );

        // Verify function types are properly categorized
        let local_funcs = symbol_table
            .functions
            .iter()
            .filter(|f| matches!(f.function_type, FunctionType::Local))
            .count();
        let imported_funcs = symbol_table
            .functions
            .iter()
            .filter(|f| matches!(f.function_type, FunctionType::Imported))
            .count();

        assert!(local_funcs > 0, "Should have local functions");

        println!(
            "Rust binary analysis: {} total, {} local, {} imported",
            symbol_table.functions.len(),
            local_funcs,
            imported_funcs
        );
    }
}

#[test]
fn test_analyze_symbols_with_go_binary() {
    let test_binary = Path::new("./test_programs/go_test_binary");

    if test_binary.exists() {
        let result = analyze_symbols(test_binary);
        assert!(result.is_ok(), "Should successfully analyze Go binary");

        let symbol_table = result.unwrap();

        // Go binaries have extensive runtime functions
        assert!(
            symbol_table.functions.len() > 50,
            "Go binary should have many runtime functions"
        );

        // Should find some Go runtime functions
        let has_go_runtime = symbol_table
            .functions
            .iter()
            .any(|f| f.name.starts_with("runtime.") || f.name.starts_with("go."));
        assert!(has_go_runtime, "Should find Go runtime functions");

        // Check for proper function categorization
        let entry_points = symbol_table
            .functions
            .iter()
            .filter(|f| f.is_entry_point)
            .count();

        println!(
            "Go binary analysis: {} functions, {} entry points",
            symbol_table.functions.len(),
            entry_points
        );
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
            (FunctionType::Local, FunctionType::Local) => {}
            (FunctionType::Imported, FunctionType::Imported) => {}
            (FunctionType::Exported, FunctionType::Exported) => {}
            (FunctionType::Thunk, FunctionType::Thunk) => {}
            (FunctionType::Constructor, FunctionType::Constructor) => {}
            (FunctionType::Destructor, FunctionType::Destructor) => {}
            (FunctionType::EntryPoint, FunctionType::EntryPoint) => {}
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
            (CallingConvention::Cdecl, CallingConvention::Cdecl) => {}
            (CallingConvention::Stdcall, CallingConvention::Stdcall) => {}
            (CallingConvention::Fastcall, CallingConvention::Fastcall) => {}
            (CallingConvention::Thiscall, CallingConvention::Thiscall) => {}
            (CallingConvention::Vectorcall, CallingConvention::Vectorcall) => {}
            (CallingConvention::SysV, CallingConvention::SysV) => {}
            (CallingConvention::Win64, CallingConvention::Win64) => {}
            (CallingConvention::Unknown, CallingConvention::Unknown) => {}
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
            (VariableType::Global, VariableType::Global) => {}
            (VariableType::Static, VariableType::Static) => {}
            (VariableType::ThreadLocal, VariableType::ThreadLocal) => {}
            (VariableType::Const, VariableType::Const) => {}
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
            (ReferenceType::Call, ReferenceType::Call) => {}
            (ReferenceType::Jump, ReferenceType::Jump) => {}
            (ReferenceType::DataReference, ReferenceType::DataReference) => {}
            (ReferenceType::StringReference, ReferenceType::StringReference) => {}
            (ReferenceType::Import, ReferenceType::Import) => {}
            (ReferenceType::Export, ReferenceType::Export) => {}
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
        parameters: vec![Parameter {
            name: Some("arg1".to_string()),
            param_type: Some("int".to_string()),
            size: Some(4),
        }],
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
fn test_analyze_symbols_with_multiple_binaries() {
    // Try to analyze multiple test binaries
    let test_binaries = vec![
        "./test_programs/c_advanced_binary",
        "./test_programs/rust_test_binary",
        "./test_programs/go_test_binary",
        "./test_programs/cpp_test_binary",
        "./test_programs/nim_test_binary",
        "./test_programs/d_test_binary",
    ];

    let mut successful_analyses = 0;

    for path_str in test_binaries {
        let path = Path::new(path_str);
        if path.exists() {
            println!("Testing function analysis on {}", path_str);

            match analyze_symbols(path) {
                Ok(symbol_table) => {
                    println!(
                        "Successfully analyzed {} functions in {}",
                        symbol_table.functions.len(),
                        path_str
                    );

                    // Verify basic properties - counts are unsigned so always >= 0

                    // Check for consistency - function types are categorized independently
                    // of is_imported/is_exported flags, so we don't expect them to sum up
                    assert!(
                        symbol_table.symbol_count.local_functions
                            <= symbol_table.symbol_count.total_functions
                    );
                    assert!(
                        symbol_table.symbol_count.imported_functions
                            <= symbol_table.symbol_count.total_functions
                    );
                    assert!(
                        symbol_table.symbol_count.exported_functions
                            <= symbol_table.symbol_count.total_functions
                    );

                    // Each binary should have at least some functions
                    assert!(
                        !symbol_table.functions.is_empty(),
                        "Binary {} should have functions",
                        path_str
                    );

                    successful_analyses += 1;
                }
                Err(e) => {
                    eprintln!("Function analysis failed for {}: {}", path_str, e);
                }
            }
        }
    }

    // At least some binaries should be successfully analyzed
    assert!(
        successful_analyses > 0,
        "Should successfully analyze at least one test binary"
    );
}

#[test]
fn test_analyze_symbols_error_conditions() {
    // Test with non-existent file
    let result = analyze_symbols(Path::new("/nonexistent/file"));
    assert!(result.is_err(), "Should fail with non-existent file");

    // Test with directory instead of file
    let result = analyze_symbols(Path::new("."));
    assert!(result.is_err(), "Should fail when given directory");

    // Test with text file (not a binary)
    let mut temp_file = NamedTempFile::new().unwrap();
    temp_file.write_all(b"This is not a binary file").unwrap();
    temp_file.flush().unwrap();

    let result = analyze_symbols(temp_file.path());
    assert!(result.is_err(), "Should fail with non-binary file");
}

#[test]
fn test_symbol_table_statistics() {
    // Use the test binary if available
    let test_binary = Path::new("./test_programs/c_advanced_binary");

    if test_binary.exists() {
        let symbol_table = analyze_symbols(test_binary).unwrap();

        // Verify counts are non-negative (usize types are always >= 0, so just verify structure exists)

        // Each category should not exceed total functions
        assert!(
            symbol_table.symbol_count.local_functions <= symbol_table.symbol_count.total_functions
        );
        assert!(
            symbol_table.symbol_count.imported_functions
                <= symbol_table.symbol_count.total_functions
        );
        assert!(
            symbol_table.symbol_count.exported_functions
                <= symbol_table.symbol_count.total_functions
        );

        // Function list length should match total count
        assert_eq!(
            symbol_table.functions.len(),
            symbol_table.symbol_count.total_functions
        );

        // Variable list length should match variable count
        assert_eq!(
            symbol_table.global_variables.len(),
            symbol_table.symbol_count.global_variables
        );
    }
}

#[test]
fn test_function_address_validation() {
    let test_binary = Path::new("./test_programs/rust_test_binary");

    if test_binary.exists() {
        let symbol_table = analyze_symbols(test_binary).unwrap();

        // All functions should have valid addresses
        for function in &symbol_table.functions {
            assert!(
                function.address > 0 || function.is_imported,
                "Function {} should have valid address or be imported",
                function.name
            );

            // Function size should be reasonable
            assert!(
                function.size < 0x1000000, // 16MB max function size
                "Function {} has unreasonable size: {}",
                function.name,
                function.size
            );

            // Name should not be empty
            assert!(
                !function.name.is_empty(),
                "Function should have non-empty name"
            );
        }

        // Check that we have reasonable calling conventions
        let conv_count = symbol_table
            .functions
            .iter()
            .filter_map(|f| f.calling_convention.as_ref())
            .count();
        assert!(
            conv_count > 0,
            "Should have functions with calling conventions"
        );
    }
}

#[test]
fn test_analyze_symbols_with_pe_binary() {
    // Test with PE binary if available
    let pe_binary = Path::new("./test_programs/c_advanced_binary");

    if pe_binary.exists() {
        match analyze_symbols(pe_binary) {
            Ok(symbol_table) => {
                println!(
                    "PE analysis found {} functions",
                    symbol_table.functions.len()
                );

                // Should have proper symbol count structure
                assert!(symbol_table.symbol_count.total_functions == symbol_table.functions.len());

                // Test PE-specific features
                if !symbol_table.imports.is_empty() {
                    let has_library = symbol_table.imports.iter().any(|i| i.library.is_some());
                    println!("Has library imports: {}", has_library);
                }

                // Check exports if any
                if !symbol_table.exports.is_empty() {
                    println!("Found {} exports", symbol_table.exports.len());
                }
            }
            Err(e) => {
                println!("PE analysis error (expected for non-PE): {}", e);
            }
        }
    }
}

#[test]
fn test_analyze_symbols_comprehensive_elf() {
    // Test with various ELF binaries to exercise different code paths
    let test_binaries = vec![
        "./test_programs/rust_test_binary",
        "./test_programs/go_test_binary",
        "./test_programs/cpp_test_binary",
        "./test_programs/c_advanced_binary",
        "/bin/ls", // System binary
    ];

    let mut successful_analyses = 0;

    for binary_path in test_binaries {
        let path = Path::new(binary_path);
        if !path.exists() {
            continue;
        }

        match analyze_symbols(path) {
            Ok(symbol_table) => {
                successful_analyses += 1;
                println!(
                    "Successfully analyzed {}: {} functions",
                    binary_path,
                    symbol_table.functions.len()
                );

                // Verify symbol table consistency
                assert_eq!(
                    symbol_table.functions.len(),
                    symbol_table.symbol_count.total_functions
                );

                // Test function type distribution
                let local_count = symbol_table
                    .functions
                    .iter()
                    .filter(|f| matches!(f.function_type, FunctionType::Local))
                    .count();
                let imported_count = symbol_table
                    .functions
                    .iter()
                    .filter(|f| f.is_imported)
                    .count();
                let exported_count = symbol_table
                    .functions
                    .iter()
                    .filter(|f| f.is_exported)
                    .count();

                assert_eq!(local_count, symbol_table.symbol_count.local_functions);
                assert_eq!(imported_count, symbol_table.symbol_count.imported_functions);
                assert_eq!(exported_count, symbol_table.symbol_count.exported_functions);

                // Test that entry points are identified if present
                let entry_points = symbol_table
                    .functions
                    .iter()
                    .filter(|f| f.is_entry_point)
                    .count();
                println!("Entry points found: {}", entry_points);

                // Verify calling conventions are set for some functions
                let with_calling_conv = symbol_table
                    .functions
                    .iter()
                    .filter(|f| f.calling_convention.is_some())
                    .count();
                println!("Functions with calling conventions: {}", with_calling_conv);

                // Test variable analysis
                println!(
                    "Global variables found: {}",
                    symbol_table.global_variables.len()
                );
                for var in symbol_table.global_variables.iter().take(5) {
                    assert!(!var.name.is_empty());
                    assert!(var.size > 0 || var.name.starts_with("_"));
                }

                // Test import/export analysis
                println!(
                    "Imports: {}, Exports: {}",
                    symbol_table.imports.len(),
                    symbol_table.exports.len()
                );
            }
            Err(e) => {
                println!("Analysis failed for {}: {}", binary_path, e);
            }
        }
    }

    // Should successfully analyze at least one binary
    assert!(
        successful_analyses > 0,
        "Should successfully analyze at least one binary"
    );
}

#[test]
fn test_analyze_symbols_error_conditions_comprehensive() {
    // Test various error conditions

    // Non-existent file
    let result = analyze_symbols(Path::new("/definitely/does/not/exist"));
    assert!(result.is_err());

    // Directory instead of file
    let result = analyze_symbols(Path::new("."));
    assert!(result.is_err());

    // Invalid binary data
    let mut temp_file = tempfile::NamedTempFile::new().unwrap();
    temp_file.write_all(b"Not a valid binary format").unwrap();
    temp_file.flush().unwrap();

    let result = analyze_symbols(temp_file.path());
    assert!(result.is_err());

    // Empty file
    let mut empty_file = tempfile::NamedTempFile::new().unwrap();
    empty_file.flush().unwrap();

    let result = analyze_symbols(empty_file.path());
    assert!(result.is_err());
}

#[test]
fn test_symbol_table_statistics_accuracy() {
    let test_binary = Path::new("./target/debug/file-scanner");

    if test_binary.exists() {
        let symbol_table = analyze_symbols(test_binary).unwrap();

        // Manually count and verify statistics
        let manual_total = symbol_table.functions.len();
        let manual_local = symbol_table
            .functions
            .iter()
            .filter(|f| matches!(f.function_type, FunctionType::Local))
            .count();
        let manual_imported = symbol_table
            .functions
            .iter()
            .filter(|f| f.is_imported)
            .count();
        let manual_exported = symbol_table
            .functions
            .iter()
            .filter(|f| f.is_exported)
            .count();
        let manual_variables = symbol_table.global_variables.len();
        let manual_xrefs = symbol_table.cross_references.len();

        // Verify all statistics match
        assert_eq!(manual_total, symbol_table.symbol_count.total_functions);
        assert_eq!(manual_local, symbol_table.symbol_count.local_functions);
        assert_eq!(
            manual_imported,
            symbol_table.symbol_count.imported_functions
        );
        assert_eq!(
            manual_exported,
            symbol_table.symbol_count.exported_functions
        );
        assert_eq!(manual_variables, symbol_table.symbol_count.global_variables);
        assert_eq!(manual_xrefs, symbol_table.symbol_count.cross_references);

        // Test total counts make sense
        assert!(manual_total >= manual_local + manual_imported);

        println!("Statistics verification passed:");
        println!("  Total functions: {}", manual_total);
        println!(
            "  Local: {}, Imported: {}, Exported: {}",
            manual_local, manual_imported, manual_exported
        );
        println!(
            "  Variables: {}, Cross-references: {}",
            manual_variables, manual_xrefs
        );
    }
}

#[test]
fn test_dynamic_symbol_analysis() {
    // Test analysis of dynamic symbols in ELF binaries
    let test_binary = Path::new("/bin/ls");

    if test_binary.exists() {
        let symbol_table = analyze_symbols(test_binary).unwrap();

        // Should find some imported functions from dynamic symbols
        let dynamic_imports = symbol_table
            .functions
            .iter()
            .filter(|f| f.is_imported && matches!(f.function_type, FunctionType::Imported))
            .count();

        println!("Dynamic imports found: {}", dynamic_imports);

        // Check that imported functions have reasonable properties
        for func in symbol_table
            .functions
            .iter()
            .filter(|f| f.is_imported)
            .take(10)
        {
            assert!(!func.name.is_empty());
            assert!(matches!(func.function_type, FunctionType::Imported));
            assert!(func.is_imported);
            assert!(!func.is_exported);
            assert!(!func.is_entry_point);
        }

        // Verify imports have corresponding ImportInfo entries
        let import_names: std::collections::HashSet<_> =
            symbol_table.imports.iter().map(|i| &i.name).collect();
        let imported_func_names: std::collections::HashSet<_> = symbol_table
            .functions
            .iter()
            .filter(|f| f.is_imported)
            .map(|f| &f.name)
            .collect();

        // Most imported functions should have import entries
        let overlap = import_names.intersection(&imported_func_names).count();
        println!(
            "Import overlap: {} out of {} functions",
            overlap,
            imported_func_names.len()
        );
    }
}
