use anyhow::Result;
use goblin::{Object, pe, elf};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Serialize, Deserialize)]
pub struct BinaryInfo {
    pub format: String,
    pub architecture: String,
    pub compiler: Option<String>,
    pub linker: Option<String>,
    pub sections: Vec<SectionInfo>,
    pub imports: Vec<String>,
    pub exports: Vec<String>,
    pub entry_point: Option<u64>,
    pub is_stripped: bool,
    pub has_debug_info: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SectionInfo {
    pub name: String,
    pub size: u64,
    pub virtual_address: u64,
    pub characteristics: String,
}

pub fn parse_binary(path: &Path) -> Result<BinaryInfo> {
    let buffer = fs::read(path)?;
    
    match Object::parse(&buffer)? {
        Object::Elf(elf) => parse_elf(elf, &buffer),
        Object::PE(pe) => parse_pe(pe, &buffer),
        Object::Mach(mach) => parse_mach(mach),
        _ => anyhow::bail!("Unsupported binary format"),
    }
}

fn parse_elf(elf: elf::Elf, _buffer: &[u8]) -> Result<BinaryInfo> {
    let mut info = BinaryInfo {
        format: "ELF".to_string(),
        architecture: match elf.header.e_machine {
            elf::header::EM_X86_64 => "x86_64",
            elf::header::EM_386 => "x86",
            elf::header::EM_ARM => "ARM",
            elf::header::EM_AARCH64 => "ARM64",
            _ => "Unknown",
        }.to_string(),
        compiler: None,
        linker: None,
        sections: Vec::new(),
        imports: Vec::new(),
        exports: Vec::new(),
        entry_point: Some(elf.header.e_entry),
        is_stripped: elf.syms.is_empty(),
        has_debug_info: false,
    };

    for section in &elf.section_headers {
        if let Some(name) = elf.shdr_strtab.get_at(section.sh_name) {
            info.sections.push(SectionInfo {
                name: name.to_string(),
                size: section.sh_size,
                virtual_address: section.sh_addr,
                characteristics: format!("{:x}", section.sh_flags),
            });

            if name.starts_with(".debug") {
                info.has_debug_info = true;
            }
        }
    }

    for import in &elf.libraries {
        info.imports.push(import.to_string());
    }

    for sym in &elf.dynsyms {
        if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
            if sym.is_function() && sym.st_bind() == elf::sym::STB_GLOBAL {
                info.exports.push(name.to_string());
            }
        }
    }

    // Note: NoteIterator parsing is version-specific
    // For simplicity, we'll check for common compiler signatures
    for section in &elf.section_headers {
        if let Some(name) = elf.shdr_strtab.get_at(section.sh_name) {
            if name.contains(".note.gnu") || name.contains(".note.ABI-tag") {
                info.compiler = Some("GCC/GNU".to_string());
                break;
            }
        }
    }

    Ok(info)
}

fn parse_pe(pe: pe::PE, _buffer: &[u8]) -> Result<BinaryInfo> {
    let mut info = BinaryInfo {
        format: "PE".to_string(),
        architecture: match pe.header.coff_header.machine {
            pe::header::COFF_MACHINE_X86_64 => "x86_64",
            pe::header::COFF_MACHINE_X86 => "x86",
            pe::header::COFF_MACHINE_ARM64 => "ARM64",
            _ => "Unknown",
        }.to_string(),
        compiler: None,
        linker: None,
        sections: Vec::new(),
        imports: Vec::new(),
        exports: Vec::new(),
        entry_point: Some(pe.entry as u64),
        is_stripped: pe.debug_data.is_none(),
        has_debug_info: pe.debug_data.is_some(),
    };

    for section in &pe.sections {
        info.sections.push(SectionInfo {
            name: section.name()?.to_string(),
            size: section.virtual_size as u64,
            virtual_address: section.virtual_address as u64,
            characteristics: format!("{:x}", section.characteristics),
        });
    }

    for import in &pe.imports {
        info.imports.push(import.name.to_string());
        // Note: In goblin 0.8, imports are handled differently
        // We already have the DLL name in import.name
    }

    // Export handling for goblin 0.8
    for export in &pe.exports {
        if let Some(name) = export.name {
            info.exports.push(name.to_string());
        }
    }

    if let Some(optional_header) = pe.header.optional_header {
        let linker_version = format!("{}.{}", 
            optional_header.standard_fields.major_linker_version,
            optional_header.standard_fields.minor_linker_version
        );
        info.linker = Some(format!("Linker v{}", linker_version));
        
        match optional_header.standard_fields.major_linker_version {
            14..=16 => info.compiler = Some("MSVC 2015-2022".to_string()),
            12..=13 => info.compiler = Some("MSVC 2013".to_string()),
            11 => info.compiler = Some("MSVC 2012".to_string()),
            10 => info.compiler = Some("MSVC 2010".to_string()),
            9 => info.compiler = Some("MSVC 2008".to_string()),
            8 => info.compiler = Some("MSVC 2005".to_string()),
            7 => info.compiler = Some("MSVC 2003".to_string()),
            6 => info.compiler = Some("MSVC 6.0".to_string()),
            2..=4 => info.compiler = Some("MinGW/GCC".to_string()),
            _ => {},
        }
    }

    Ok(info)
}

fn parse_mach(mach: goblin::mach::Mach) -> Result<BinaryInfo> {
    use goblin::mach::Mach;
    
    let mut info = BinaryInfo {
        format: "Mach-O".to_string(),
        architecture: "Unknown".to_string(),
        compiler: Some("Apple Clang".to_string()),
        linker: Some("Apple LD".to_string()),
        sections: Vec::new(),
        imports: Vec::new(),
        exports: Vec::new(),
        entry_point: None,
        is_stripped: false,
        has_debug_info: false,
    };

    match mach {
        Mach::Binary(mach_o) => {
            info.architecture = if mach_o.is_64 { "x86_64" } else { "x86" }.to_string();
            info.entry_point = Some(mach_o.entry as u64);
        for segment in &mach_o.segments {
            for (section, _) in &segment.sections()? {
                info.sections.push(SectionInfo {
                    name: section.name()?.to_string(),
                    size: section.size,
                    virtual_address: section.addr,
                    characteristics: format!("{:x}", section.flags),
                });
            }
        }

            info.is_stripped = mach_o.symbols.is_none();
            
            for import in &mach_o.imports()? {
                info.imports.push(import.name.to_string());
            }

            let exports = mach_o.exports()?;
            if !exports.is_empty() {
                for export in exports {
                    info.exports.push(export.name.to_string());
                }
            }
        }
        Mach::Fat(_) => {
            info.architecture = "Universal".to_string();
        }
    }

    Ok(info)
}