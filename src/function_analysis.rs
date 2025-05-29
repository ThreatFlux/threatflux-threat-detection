use anyhow::Result;
use goblin::{elf, pe, mach, Object};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Read;
use std::path::Path;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FunctionInfo {
    pub name: String,
    pub address: u64,
    pub size: u64,
    pub function_type: FunctionType,
    pub calling_convention: Option<CallingConvention>,
    pub parameters: Vec<Parameter>,
    pub is_entry_point: bool,
    pub is_exported: bool,
    pub is_imported: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum FunctionType {
    Local,
    Imported,
    Exported,
    Thunk,
    Constructor,
    Destructor,
    EntryPoint,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum CallingConvention {
    Cdecl,
    Stdcall,
    Fastcall,
    Thiscall,
    Vectorcall,
    SysV,
    Win64,
    Unknown,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Parameter {
    pub name: Option<String>,
    pub param_type: Option<String>,
    pub size: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VariableInfo {
    pub name: String,
    pub address: u64,
    pub size: u64,
    pub var_type: VariableType,
    pub section: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum VariableType {
    Global,
    Static,
    ThreadLocal,
    Const,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CrossReference {
    pub from_address: u64,
    pub to_address: u64,
    pub reference_type: ReferenceType,
    pub instruction_type: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum ReferenceType {
    Call,
    Jump,
    DataReference,
    StringReference,
    Import,
    Export,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SymbolTable {
    pub functions: Vec<FunctionInfo>,
    pub global_variables: Vec<VariableInfo>,
    pub cross_references: Vec<CrossReference>,
    pub imports: Vec<ImportInfo>,
    pub exports: Vec<ExportInfo>,
    pub symbol_count: SymbolCounts,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ImportInfo {
    pub name: String,
    pub library: Option<String>,
    pub address: Option<u64>,
    pub ordinal: Option<u16>,
    pub is_delayed: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ExportInfo {
    pub name: String,
    pub address: u64,
    pub ordinal: Option<u16>,
    pub is_forwarder: bool,
    pub forwarder_name: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SymbolCounts {
    pub total_functions: usize,
    pub local_functions: usize,
    pub imported_functions: usize,
    pub exported_functions: usize,
    pub global_variables: usize,
    pub cross_references: usize,
}

pub fn analyze_symbols(path: &Path) -> Result<SymbolTable> {
    let mut file = File::open(path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    match Object::parse(&buffer)? {
        Object::Elf(elf) => analyze_elf_symbols(elf, &buffer),
        Object::PE(pe) => analyze_pe_symbols(pe, &buffer),
        Object::Mach(mach) => analyze_mach_symbols(mach, &buffer),
        _ => Err(anyhow::anyhow!("Unsupported binary format for symbol analysis")),
    }
}

fn analyze_elf_symbols(elf: elf::Elf, _buffer: &[u8]) -> Result<SymbolTable> {
    let mut functions = Vec::new();
    let mut global_variables = Vec::new();
    let mut imports = Vec::new();
    let mut exports = Vec::new();
    let cross_references = Vec::new();

    // Analyze ELF symbols
    for sym in elf.syms.iter() {
        let name = elf.strtab.get_at(sym.st_name).unwrap_or("").to_string();
        
        if name.is_empty() || name.starts_with("$") {
            continue;
        }

        let sym_type = sym.st_type();
        let binding = sym.st_bind();
        let address = sym.st_value;
        let size = sym.st_size;

        match sym_type {
            goblin::elf::sym::STT_FUNC => {
                let function_type = match binding {
                    goblin::elf::sym::STB_GLOBAL => {
                        if sym.st_shndx == 0 {
                            FunctionType::Imported
                        } else {
                            FunctionType::Exported
                        }
                    }
                    goblin::elf::sym::STB_LOCAL => FunctionType::Local,
                    _ => FunctionType::Local,
                };

                let is_entry_point = name == "_start" || name == "main" || address == elf.header.e_entry;
                let is_exported = binding == goblin::elf::sym::STB_GLOBAL && sym.st_shndx != 0;
                let is_imported = sym.st_shndx == 0;

                functions.push(FunctionInfo {
                    name: name.clone(),
                    address,
                    size,
                    function_type,
                    calling_convention: Some(CallingConvention::SysV),
                    parameters: Vec::new(), // Would need debug info for this
                    is_entry_point,
                    is_exported,
                    is_imported,
                });

                // Add to imports/exports lists
                if is_imported {
                    imports.push(ImportInfo {
                        name: name.clone(),
                        library: None, // ELF doesn't directly specify library
                        address: if address != 0 { Some(address) } else { None },
                        ordinal: None,
                        is_delayed: false,
                    });
                } else if is_exported {
                    exports.push(ExportInfo {
                        name: name.clone(),
                        address,
                        ordinal: None,
                        is_forwarder: false,
                        forwarder_name: None,
                    });
                }
            }
            goblin::elf::sym::STT_OBJECT => {
                if binding == goblin::elf::sym::STB_GLOBAL || binding == goblin::elf::sym::STB_LOCAL {
                    global_variables.push(VariableInfo {
                        name: name.clone(),
                        address,
                        size,
                        var_type: if binding == goblin::elf::sym::STB_GLOBAL {
                            VariableType::Global
                        } else {
                            VariableType::Static
                        },
                        section: None, // Could be enhanced to include section name
                    });
                }
            }
            _ => {}
        }
    }

    // Analyze dynamic symbols if available
    for sym in elf.dynsyms.iter() {
        let name = elf.dynstrtab.get_at(sym.st_name).unwrap_or("").to_string();
        
        if name.is_empty() || functions.iter().any(|f| f.name == name) {
            continue;
        }

        if sym.st_type() == goblin::elf::sym::STT_FUNC && sym.st_shndx == 0 {
            // This is an imported function
            functions.push(FunctionInfo {
                name: name.clone(),
                address: sym.st_value,
                size: sym.st_size,
                function_type: FunctionType::Imported,
                calling_convention: Some(CallingConvention::SysV),
                parameters: Vec::new(),
                is_entry_point: false,
                is_exported: false,
                is_imported: true,
            });

            imports.push(ImportInfo {
                name: name.clone(),
                library: None,
                address: if sym.st_value != 0 { Some(sym.st_value) } else { None },
                ordinal: None,
                is_delayed: false,
            });
        }
    }

    let symbol_count = SymbolCounts {
        total_functions: functions.len(),
        local_functions: functions.iter().filter(|f| matches!(f.function_type, FunctionType::Local)).count(),
        imported_functions: functions.iter().filter(|f| f.is_imported).count(),
        exported_functions: functions.iter().filter(|f| f.is_exported).count(),
        global_variables: global_variables.len(),
        cross_references: cross_references.len(),
    };

    Ok(SymbolTable {
        functions,
        global_variables,
        cross_references,
        imports,
        exports,
        symbol_count,
    })
}

fn analyze_pe_symbols(pe: pe::PE, _buffer: &[u8]) -> Result<SymbolTable> {
    let mut functions = Vec::new();
    let global_variables = Vec::new();
    let mut imports = Vec::new();
    let mut exports = Vec::new();
    let cross_references = Vec::new();

    // Analyze PE imports
    for import in pe.imports.iter() {
        imports.push(ImportInfo {
            name: import.name.to_string(),
            library: Some(import.dll.to_string()),
            address: Some(import.rva as u64),
            ordinal: Some(import.ordinal),
            is_delayed: false, // Would need to check delay import table
        });

        // Add imported functions to function list
        functions.push(FunctionInfo {
            name: import.name.to_string(),
            address: import.rva as u64,
            size: 0, // PE imports don't have size info
            function_type: FunctionType::Imported,
            calling_convention: Some(CallingConvention::Stdcall), // Common for Windows
            parameters: Vec::new(),
            is_entry_point: false,
            is_exported: false,
            is_imported: true,
        });
    }

    // Analyze PE exports
    for export in pe.exports.iter() {
        let export_name = export.name.unwrap_or("").to_string();
        let export_address = export.rva as u64;
        
        exports.push(ExportInfo {
            name: export_name.clone(),
            address: export_address,
            ordinal: None, // PE exports don't always have ordinals in goblin
            is_forwarder: export.reexport.is_some(),
            forwarder_name: if export.reexport.is_some() { Some("forwarded".to_string()) } else { None },
        });

        // Add exported functions to function list
        if export.name.is_some() {
            // For PE files, we'll consider main/WinMain/DllMain as potential entry points
            let name = export.name.unwrap();
            let is_entry_point = name == "main" || name == "WinMain" || name == "DllMain";
            
            functions.push(FunctionInfo {
                name: export_name.clone(),
                address: export_address,
                size: 0, // PE doesn't provide function sizes
                function_type: FunctionType::Exported,
                calling_convention: Some(CallingConvention::Stdcall),
                parameters: Vec::new(),
                is_entry_point,
                is_exported: true,
                is_imported: false,
            });
        }
    }

    let symbol_count = SymbolCounts {
        total_functions: functions.len(),
        local_functions: functions.iter().filter(|f| matches!(f.function_type, FunctionType::Local)).count(),
        imported_functions: functions.iter().filter(|f| f.is_imported).count(),
        exported_functions: functions.iter().filter(|f| f.is_exported).count(),
        global_variables: global_variables.len(),
        cross_references: cross_references.len(),
    };

    Ok(SymbolTable {
        functions,
        global_variables,
        cross_references,
        imports,
        exports,
        symbol_count,
    })
}

fn analyze_mach_symbols(mach: mach::Mach, _buffer: &[u8]) -> Result<SymbolTable> {
    let mut functions = Vec::new();
    let mut global_variables = Vec::new();
    let mut imports = Vec::new();
    let mut exports = Vec::new();
    let cross_references = Vec::new();

    match mach {
        mach::Mach::Fat(_) => {
            // For fat binaries, we'd need to choose an architecture
            // For now, return empty symbol table
        }
        mach::Mach::Binary(macho) => {
            // Analyze Mach-O symbols
            for sym in macho.symbols().flatten() {
                let name = sym.0.to_string();
                let nlist = sym.1;
                
                if name.is_empty() || name.starts_with("__") {
                    continue;
                }

                let address = nlist.n_value;
                let is_external = nlist.is_global();
                
                // Check if this is a function symbol (simplified check)
                if nlist.n_type & mach::symbols::N_TYPE == mach::symbols::N_SECT {
                    let function_type = if is_external {
                        FunctionType::Exported
                    } else {
                        FunctionType::Local
                    };

                    let is_entry_point = name == "_main" || name == "main";

                    functions.push(FunctionInfo {
                        name: name.clone(),
                        address,
                        size: 0, // Mach-O doesn't provide function sizes directly
                        function_type,
                        calling_convention: Some(CallingConvention::SysV),
                        parameters: Vec::new(),
                        is_entry_point,
                        is_exported: is_external,
                        is_imported: false,
                    });

                    if is_external {
                        exports.push(ExportInfo {
                            name: name.clone(),
                            address,
                            ordinal: None,
                            is_forwarder: false,
                            forwarder_name: None,
                        });
                    }
                } else if nlist.n_type & mach::symbols::N_TYPE == mach::symbols::N_SECT && !name.contains("func") {
                    global_variables.push(VariableInfo {
                        name: name.clone(),
                        address,
                        size: 0, // Size not available
                        var_type: if is_external {
                            VariableType::Global
                        } else {
                            VariableType::Static
                        },
                        section: None,
                    });
                }
            }

            // Analyze imports (undefined symbols)
            for sym in macho.symbols().flatten() {
                let name = sym.0.to_string();
                let nlist = sym.1;
                
                if nlist.is_undefined() && !name.is_empty() {
                    imports.push(ImportInfo {
                        name: name.clone(),
                        library: None, // Mach-O doesn't specify library directly
                        address: None,
                        ordinal: None,
                        is_delayed: false,
                    });

                    functions.push(FunctionInfo {
                        name: name.clone(),
                        address: 0,
                        size: 0,
                        function_type: FunctionType::Imported,
                        calling_convention: Some(CallingConvention::SysV),
                        parameters: Vec::new(),
                        is_entry_point: false,
                        is_exported: false,
                        is_imported: true,
                    });
                }
            }
        }
    }

    let symbol_count = SymbolCounts {
        total_functions: functions.len(),
        local_functions: functions.iter().filter(|f| matches!(f.function_type, FunctionType::Local)).count(),
        imported_functions: functions.iter().filter(|f| f.is_imported).count(),
        exported_functions: functions.iter().filter(|f| f.is_exported).count(),
        global_variables: global_variables.len(),
        cross_references: cross_references.len(),
    };

    Ok(SymbolTable {
        functions,
        global_variables,
        cross_references,
        imports,
        exports,
        symbol_count,
    })
}