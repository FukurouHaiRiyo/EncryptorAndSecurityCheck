use goblin::pe::PE;
use std::fs;
use std::path::Path;

/// A struct to hold extracted PE information.
pub struct PeInfo {
    pub machine: String,              // CPU architecture (e.g., x86, x64)
    pub number_of_sections: usize,   // Number of sections in the PE file
    pub timestamp: u32,              // Timestamp when the file was created
    pub entry_point: u32,            // Entry point address of the executable
    pub image_base: u64,             // Preferred load address of the executable
    pub sections: Vec<String>,       // List of section names
}

/// Analyzes a PE (Portable Executable) file and extracts key header and section information.
///
/// # Arguments
/// * `path` - A reference to the file path of the PE binary.
///
/// # Returns
/// A `PeInfo` struct on success or an error message as a `String`.
pub fn analyze_pe_file<P: AsRef<Path>>(path: P) -> Result<PeInfo, String> {
    // Read the file into a byte buffer
    let buffer = fs::read(path).map_err(|e| format!("Failed to read file: {}", e))?;
    
    // Parse the PE file using goblin
    let pe = PE::parse(&buffer).map_err(|e| format!("Failed to parse PE file: {}", e))?;

    // Extract and return the information from the PE headers
    Ok(PeInfo {
        machine: format!("{:?}", pe.header.coff_header.machine),
        number_of_sections: pe.sections.len(),
        timestamp: pe.header.coff_header.time_date_stamp,
        entry_point: pe.entry,
        image_base: pe.image_base,
        sections: pe.sections.iter().map(|s| String::from_utf8_lossy(&s.name).to_string()).collect(),
    })
}
