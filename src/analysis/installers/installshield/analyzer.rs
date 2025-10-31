use camino::Utf8PathBuf;
use flate2::read::ZlibDecoder;
use msi::Language;
use std::io::{Cursor, Read, Seek, SeekFrom};
use tracing::debug;
use winget_types::{
    LanguageTag,
    installer::{Architecture, InstallationMetadata, Installer, InstallerType, Scope},
};
use yara_x::mods::PE;

use super::error::InstallShieldError;
use crate::analysis::installers::msi::Msi;
use crate::{analysis::Installers, traits::FromMachine};

// Constants
const ISSIG: &[u8; 13] = b"InstallShield";
const ISSIG_STRM: &[u8; 13] = b"ISSetupStream";
const MAGIC_DEC: [u8; 4] = [0x13, 0x35, 0x86, 0x07];

// Data structures matching C structs
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
struct IsHeader {
    sig: [u8; 14],
    num_files: u16,
    type_field: u32,
    x4: [u8; 8],
    x5: u16,
    x6: [u8; 16],
}

#[repr(C, packed)]
#[derive(Debug, Clone)]
struct IsFileAttributes {
    file_name: [u8; 260], // _MAX_PATH
    encoded_flags: u32,
    x3: u32,
    file_len: u32,
    x5: [u8; 8],
    is_unicode_launcher: u16,
    x7: [u8; 30],
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
struct IsFileAttributesX {
    filename_len: u32,
    encoded_flags: u32,
    x3: [u8; 2],
    file_len: u32,
    x5: [u8; 8],
    is_unicode_launcher: u16,
}

pub struct InstallShield {
    pub file_count: u16,
    pub file_names: Vec<String>,
    pub primary_language: Option<u16>,
    pub install_location: Option<String>,
    pub architecture: Architecture,
    pub setup_ini_content: Option<String>,
    pub product_name: Option<String>,
    pub product_version: Option<String>,
    pub product_code: Option<String>,
    pub msi: Option<Msi>,
    pub installshield_version: Option<String>,
}

impl InstallShield {
    pub fn new<R: Read + Seek>(reader: &mut R, pe: &PE) -> Result<Self, InstallShieldError> {
        // Get data offset (after last PE section)
        let mut data_offset = Self::get_data_offset(reader, pe)?;

        // Try to skip version signature like "NB10" that may appear before InstallShield header
        reader.seek(SeekFrom::Start(data_offset))?;

        // Read a small buffer to check for version signature
        let mut prefix = [0u8; 16];
        if reader.read(&mut prefix).is_ok() {
            // Check for "NB10" or similar version signatures
            if &prefix[..4] == b"NB10" {
                // Skip past the version signature block
                // The C code uses fscanf with patterns to skip, we'll look for the signature
                reader.seek(SeekFrom::Start(data_offset))?;
                let mut search_buf = vec![0u8; 512];
                if let Ok(n) = reader.read(&mut search_buf) {
                    // Look for "InstallShield" or "ISSetupStream" in the buffer
                    if let Some(pos) = search_buf
                        .windows(13)
                        .position(|w| w == ISSIG || w == ISSIG_STRM)
                    {
                        data_offset += pos as u64;
                    }
                }
            }
        }

        // Try to read InstallShield header
        reader.seek(SeekFrom::Start(data_offset))?;

        let header = Self::read_header(reader)?;

        // Verify signature
        if &header.sig[..13] != ISSIG && &header.sig[..13] != ISSIG_STRM {
            return Err(InstallShieldError::NotInstallShieldFile);
        }

        let num_files = header.num_files;
        let _type_field = header.type_field;
        let is_stream = &header.sig[..13] == ISSIG_STRM;

        // We'll detect version later after parsing MSI (if available)

        debug!("Found InstallShield installer with {} files", num_files);

        // Parse file names and extract file data
        let mut file_names = Vec::new();
        let mut file_data_map: Vec<(String, u64, u32, u32)> = Vec::new(); // (name, offset, size, flags)
        let mut current_offset = data_offset + std::mem::size_of::<IsHeader>() as u64;

        for _i in 0..num_files {
            reader.seek(SeekFrom::Start(current_offset))?;

            if is_stream {
                // ISSetupStream format uses IS_FILE_ATTRIBUTES_X
                match Self::read_file_attributes_x(reader) {
                    Ok(attrs) => {
                        // Read UTF-16 filename
                        let mut filename_bytes = vec![0u8; attrs.filename_len as usize];
                        reader.read_exact(&mut filename_bytes)?;

                        // Convert UTF-16 to String
                        let u16_chars: Vec<u16> = filename_bytes
                            .chunks_exact(2)
                            .map(|c| u16::from_le_bytes([c[0], c[1]]))
                            .collect();

                        if let Ok(filename) = String::from_utf16(&u16_chars) {
                            let filename = filename.trim_end_matches('\0').to_string();
                            let data_offset_for_file = reader.stream_position()?;
                            file_data_map.push((
                                filename.clone(),
                                data_offset_for_file,
                                attrs.file_len,
                                attrs.encoded_flags,
                            ));
                            file_names.push(filename);
                        }

                        current_offset = reader.stream_position()?;
                        current_offset += attrs.file_len as u64;
                    }
                    Err(_) => break,
                }
            } else {
                // Standard format uses IS_FILE_ATTRIBUTES
                match Self::read_file_attributes(reader) {
                    Ok(attrs) => {
                        // Convert null-terminated filename to String
                        let filename_end = attrs
                            .file_name
                            .iter()
                            .position(|&c| c == 0)
                            .unwrap_or(attrs.file_name.len());
                        if let Ok(filename) =
                            String::from_utf8(attrs.file_name[..filename_end].to_vec())
                        {
                            let data_offset_for_file = reader.stream_position()?;
                            file_data_map.push((
                                filename.clone(),
                                data_offset_for_file,
                                attrs.file_len,
                                attrs.encoded_flags,
                            ));
                            file_names.push(filename);
                        }

                        current_offset = reader.stream_position()?;
                        current_offset += attrs.file_len as u64;
                    }
                    Err(_) => break,
                }
            }
        }

        debug!("Parsed {} file names", file_names.len());
        if !file_names.is_empty() {
            debug!(
                "First few files: {:?}",
                &file_names[..std::cmp::min(100, file_names.len())]
            );
        }

        // Try to extract and parse Setup.ini
        let mut setup_ini_content = None;
        if let Some((filename, offset, size, flags)) = file_data_map
            .iter()
            .find(|(name, _, _, _)| name.eq_ignore_ascii_case("Setup.ini"))
        {
            debug!("Found Setup.ini at offset 0x{:X}, size {}", offset, size);

            setup_ini_content = Self::extract_and_decrypt_file(
                reader, filename, *offset, *size, *flags, is_stream,
            )?;

            if let Some(ref content) = setup_ini_content {
                debug!("Setup.ini contents:\n{}", content);
            }
        }

        // Try to extract and parse language INI file
        if let Some(lang_ini_name) = file_names
            .iter()
            .find(|name| name.ends_with(".ini") && name.starts_with("0x"))
        {
            if let Some((filename, offset, size, flags)) = file_data_map
                .iter()
                .find(|(name, _, _, _)| name == lang_ini_name)
            {
                debug!(
                    "Found language file {} at offset 0x{:X}, size {}",
                    filename, offset, size
                );

                if let Ok(Some(content)) = Self::extract_and_decrypt_file(
                    reader, filename, *offset, *size, *flags, is_stream,
                ) {
                    debug!("Language INI ({}) contents:\n{}", filename, content);
                }
            }
        }

        // Parse Setup.ini for metadata
        let (product_name, product_version, product_code, setup_ini_language, msi_package_name) =
            if let Some(ref ini) = setup_ini_content {
                Self::parse_setup_ini_metadata(ini)
            } else {
                (None, None, None, None, None)
            };

        // Try to extract and analyze the MSI if referenced in Setup.ini
        let msi = if let Some(ref package_name) = msi_package_name {
            if let Some((filename, offset, size, flags)) = file_data_map
                .iter()
                .find(|(name, _, _, _)| name.eq_ignore_ascii_case(package_name))
            {
                debug!(
                    "Found MSI package {} at offset 0x{:X}, size {}",
                    filename, offset, size
                );

                // Extract the MSI file data
                reader.seek(SeekFrom::Start(*offset))?;
                let mut msi_data = vec![0u8; *size as usize];
                reader.read_exact(&mut msi_data)?;

                // Check if encrypted and decrypt if needed
                let needs_decryption = (flags & 0x6) != 0;
                if needs_decryption {
                    debug!("MSI is encrypted, decrypting...");
                    let seed = filename.as_bytes();
                    let key = Self::gen_key(seed);
                    let has_type_4 = (flags & 0x4) != 0;
                    let has_type_2 = (flags & 0x2) != 0;

                    if has_type_4 && has_type_2 {
                        let mut decoded_pos = 0;
                        while decoded_pos < msi_data.len() {
                            let block_size = std::cmp::min(1024, msi_data.len() - decoded_pos);
                            Self::decode_data(
                                &mut msi_data[decoded_pos..decoded_pos + block_size],
                                0,
                                &key,
                            );
                            decoded_pos += block_size;
                        }
                    } else if !has_type_4 && has_type_2 {
                        Self::decode_data(&mut msi_data, 0, &key);
                    }

                    // Check if the decrypted data is zlib compressed
                    if msi_data.len() >= 2
                        && (msi_data[0] == 0x78
                            && (msi_data[1] == 0x9C || msi_data[1] == 0x01 || msi_data[1] == 0xDA))
                    {
                        debug!("MSI is zlib compressed, decompressing...");
                        let mut decoder = ZlibDecoder::new(&msi_data[..]);
                        let mut decompressed = Vec::new();
                        if decoder.read_to_end(&mut decompressed).is_ok() {
                            debug!("Decompressed MSI to {} bytes", decompressed.len());
                            msi_data = decompressed;
                        } else {
                            debug!("Failed to decompress MSI, using encrypted version");
                        }
                    }
                }

                // Try to parse the MSI
                let cursor = Cursor::new(msi_data);
                match Msi::new(cursor) {
                    Ok(msi) => {
                        debug!("Successfully parsed MSI package");
                        if let Some(ref creating_app) = msi.creating_application {
                            debug!("MSI created by: {}", creating_app);
                        }
                        Some(msi)
                    }
                    Err(e) => {
                        debug!("Failed to parse MSI: {}", e);
                        None
                    }
                }
            } else {
                debug!("MSI package {} not found in file list", package_name);
                None
            }
        } else {
            None
        };

        // Extract primary language - prefer Setup.ini Default language over language files
        let primary_language = setup_ini_language.or_else(|| {
            file_names.iter().find_map(|name| {
                if name.ends_with(".ini") && name.starts_with("0x") {
                    let hex_str = name.strip_prefix("0x")?.strip_suffix(".ini")?;
                    u16::from_str_radix(hex_str, 16).ok()
                } else {
                    None
                }
            })
        });

        if let Some(lang_id) = primary_language {
            debug!("Detected primary language: 0x{:04X}", lang_id);
        }

        // Look for common install location indicators in filenames
        let install_location =
            Self::detect_install_location(&file_names, setup_ini_content.as_deref());

        let architecture = Architecture::from_machine(pe.machine());

        // Detect InstallShield version from MSI if available, otherwise from header
        let installshield_version = msi
            .as_ref()
            .and_then(|m| m.creating_application.as_deref())
            .and_then(|app| Self::parse_installshield_version(app))
            .or_else(|| Self::detect_version(&header));

        if let Some(ref version) = installshield_version {
            debug!("Detected InstallShield version: {}", version);
        }

        Ok(Self {
            file_count: num_files,
            file_names,
            primary_language,
            install_location,
            architecture,
            setup_ini_content,
            product_name,
            product_version,
            product_code,
            msi,
            installshield_version,
        })
    }

    fn parse_installshield_version(creating_app: &str) -> Option<String> {
        // MSI creating_application typically contains "InstallShield" and version
        // Examples:
        // - "InstallShield 2020"
        // - "InstallShield Premier - 11.5.0.123"
        // - "InstallShield 12.0"

        if creating_app.contains("InstallShield") {
            // Try to extract version number
            if let Some(version_part) = creating_app
                .split_whitespace()
                .find(|s| s.chars().next().map_or(false, |c| c.is_ascii_digit()) && s.contains('.'))
            {
                return Some(version_part.to_string());
            }

            // Try to find year-based version (2018, 2019, 2020, etc.)
            if let Some(year) = creating_app.split_whitespace().find(|s| {
                s.len() == 4 && s.chars().all(|c| c.is_ascii_digit()) && s.starts_with("20")
            }) {
                return Some(year.to_string());
            }

            // Return the whole string if we can't parse it
            return Some(creating_app.to_string());
        }

        None
    }

    fn detect_version(header: &IsHeader) -> Option<String> {
        // The 14th byte (index 13) of the signature often indicates version
        // type_field also contains version information
        let version_byte = header.sig[13];

        // Based on reverse engineering of InstallShield installers:
        // - Early versions (5.x): sig[13] = 0x01
        // - Version 6.x: sig[13] = 0x02
        // - Version 7.x-9.x: sig[13] = 0x03
        // - Version 10.x-11.x: sig[13] = 0x04
        // - Version 12.x+: sig[13] = 0x05 or higher
        // ISSetupStream format introduced in IS 12

        let is_stream = &header.sig[..13] == ISSIG_STRM;

        if is_stream {
            // ISSetupStream format was introduced in InstallShield 12
            // type_field can give more granular version info
            match header.type_field {
                0..=0x01000000 => Some("12.x".to_string()),
                0x01000001..=0x01ffffff => Some("2008-2009".to_string()),
                0x02000000..=0x02ffffff => Some("2010-2011".to_string()),
                0x03000000..=0x03ffffff => Some("2012-2013".to_string()),
                0x04000000..=0x04ffffff => Some("2014-2015".to_string()),
                _ => Some("12.x or later".to_string()),
            }
        } else {
            // Legacy InstallShield format
            match version_byte {
                0x01 => Some("5.x".to_string()),
                0x02 => Some("6.x".to_string()),
                0x03 => Some("7.x-9.x".to_string()),
                0x04 => Some("10.x-11.x".to_string()),
                0x05 => Some("11.x-12.x".to_string()),
                _ => Some(format!("Unknown (sig[13]=0x{:02X})", version_byte)),
            }
        }
    }

    fn get_data_offset<R: Read + Seek>(reader: &mut R, pe: &PE) -> Result<u64, InstallShieldError> {
        // Find the last section and calculate offset after it
        if let Some(last_section) = pe.sections.last() {
            let offset =
                last_section.raw_data_offset() as u64 + last_section.raw_data_size() as u64;
            Ok(offset)
        } else {
            Err(InstallShieldError::InvalidHeader)
        }
    }

    fn read_header<R: Read>(reader: &mut R) -> Result<IsHeader, InstallShieldError> {
        let mut header = IsHeader {
            sig: [0; 14],
            num_files: 0,
            type_field: 0,
            x4: [0; 8],
            x5: 0,
            x6: [0; 16],
        };

        // Read header fields
        reader.read_exact(&mut header.sig)?;

        let mut buf = [0u8; 2];
        reader.read_exact(&mut buf)?;
        header.num_files = u16::from_le_bytes(buf);

        let mut buf = [0u8; 4];
        reader.read_exact(&mut buf)?;
        header.type_field = u32::from_le_bytes(buf);

        reader.read_exact(&mut header.x4)?;

        let mut buf = [0u8; 2];
        reader.read_exact(&mut buf)?;
        header.x5 = u16::from_le_bytes(buf);

        reader.read_exact(&mut header.x6)?;

        Ok(header)
    }

    fn read_file_attributes<R: Read>(
        reader: &mut R,
    ) -> Result<IsFileAttributes, InstallShieldError> {
        let mut attrs = IsFileAttributes {
            file_name: [0; 260],
            encoded_flags: 0,
            x3: 0,
            file_len: 0,
            x5: [0; 8],
            is_unicode_launcher: 0,
            x7: [0; 30],
        };

        reader.read_exact(&mut attrs.file_name)?;

        let mut buf = [0u8; 4];
        reader.read_exact(&mut buf)?;
        attrs.encoded_flags = u32::from_le_bytes(buf);

        reader.read_exact(&mut buf)?;
        attrs.x3 = u32::from_le_bytes(buf);

        reader.read_exact(&mut buf)?;
        attrs.file_len = u32::from_le_bytes(buf);

        reader.read_exact(&mut attrs.x5)?;

        let mut buf = [0u8; 2];
        reader.read_exact(&mut buf)?;
        attrs.is_unicode_launcher = u16::from_le_bytes(buf);

        reader.read_exact(&mut attrs.x7)?;

        Ok(attrs)
    }

    fn read_file_attributes_x<R: Read>(
        reader: &mut R,
    ) -> Result<IsFileAttributesX, InstallShieldError> {
        let mut attrs = IsFileAttributesX {
            filename_len: 0,
            encoded_flags: 0,
            x3: [0; 2],
            file_len: 0,
            x5: [0; 8],
            is_unicode_launcher: 0,
        };

        let mut buf = [0u8; 4];
        reader.read_exact(&mut buf)?;
        attrs.filename_len = u32::from_le_bytes(buf);

        reader.read_exact(&mut buf)?;
        attrs.encoded_flags = u32::from_le_bytes(buf);

        reader.read_exact(&mut attrs.x3)?;

        reader.read_exact(&mut buf)?;
        attrs.file_len = u32::from_le_bytes(buf);

        reader.read_exact(&mut attrs.x5)?;

        let mut buf = [0u8; 2];
        reader.read_exact(&mut buf)?;
        attrs.is_unicode_launcher = u16::from_le_bytes(buf);

        Ok(attrs)
    }

    // Generate decryption key from seed
    fn gen_key(seeds: &[u8]) -> Vec<u8> {
        seeds
            .iter()
            .enumerate()
            .map(|(i, &seed)| seed ^ MAGIC_DEC[i % MAGIC_DEC.len()])
            .collect()
    }

    // Helper function to extract and decrypt a file from the archive
    fn extract_and_decrypt_file<R: Read + Seek>(
        reader: &mut R,
        filename: &str,
        offset: u64,
        size: u32,
        flags: u32,
        is_stream: bool,
    ) -> Result<Option<String>, InstallShieldError> {
        reader.seek(SeekFrom::Start(offset))?;
        let mut file_data = vec![0u8; size as usize];
        reader.read_exact(&mut file_data)?;

        debug!(
            "{} raw first bytes: {:02X?}",
            filename,
            &file_data[..std::cmp::min(20, file_data.len())]
        );

        // Check if file needs decryption based on flags
        let needs_decryption = (flags & 0x6) != 0;
        if needs_decryption {
            debug!(
                "{} is encrypted (flags: 0x{:X}), attempting to decrypt",
                filename, flags
            );

            // Generate decryption key from filename
            let seed = filename.as_bytes();
            let key = Self::gen_key(seed);

            // Determine decoding method based on flags
            let has_type_4 = (flags & 0x4) != 0;
            let has_type_2 = (flags & 0x2) != 0;

            debug!(
                "Decryption flags - has_type_4: {}, has_type_2: {}, key_len: {}",
                has_type_4,
                has_type_2,
                key.len()
            );

            if has_type_4 && has_type_2 {
                // Block-based decoding (1024 bytes) per C code
                debug!("Using block-based decoding (1024 bytes)");
                let mut decoded_pos = 0;
                while decoded_pos < file_data.len() {
                    let block_size = std::cmp::min(1024, file_data.len() - decoded_pos);
                    Self::decode_data(
                        &mut file_data[decoded_pos..decoded_pos + block_size],
                        0,
                        &key,
                    );
                    decoded_pos += block_size;
                }
            } else if !has_type_4 && has_type_2 {
                // Full file decoding
                debug!("Using full file decoding");
                Self::decode_data(&mut file_data, 0, &key);
            }
        }

        // Try to convert to string
        if let Ok(content) = String::from_utf8(file_data.clone()) {
            return Ok(Some(content));
        } else if file_data.len() >= 2
            && file_data[0] == 0x78
            && (file_data[1] == 0x9C || file_data[1] == 0x01 || file_data[1] == 0xDA)
        {
            // Try to decompress with zlib (starts with 78 9C, 78 01, or 78 DA)
            debug!("Data appears to be zlib compressed, attempting to decompress");
            let mut decoder = ZlibDecoder::new(&file_data[..]);
            let mut decompressed = Vec::new();
            if decoder.read_to_end(&mut decompressed).is_ok() {
                debug!("Decompressed {} bytes", decompressed.len());
                debug!(
                    "Decompressed first bytes: {:02X?}",
                    &decompressed[..std::cmp::min(100, decompressed.len())]
                );

                // Try UTF-8 first
                if let Ok(content) = String::from_utf8(decompressed.clone()) {
                    return Ok(Some(content));
                } else {
                    // Try UTF-16 LE (common in Windows)
                    if decompressed.len() >= 2 && decompressed.len() % 2 == 0 {
                        let u16_data: Vec<u16> = decompressed
                            .chunks_exact(2)
                            .map(|c| u16::from_le_bytes([c[0], c[1]]))
                            .collect();
                        if let Ok(content) = String::from_utf16(&u16_data) {
                            return Ok(Some(content));
                        }
                    }
                }
            }
        }

        debug!("{} could not be decoded as text", filename);
        Ok(None)
    }

    // Decode a single byte
    fn decode_byte(byte: u8, key: u8) -> u8 {
        !(key ^ (byte.wrapping_shl(4) | byte.wrapping_shr(4)))
    }

    // Decode data with key
    fn decode_data(data: &mut [u8], offset: usize, key: &[u8]) {
        if key.is_empty() {
            return;
        }

        for (i, byte) in data.iter_mut().enumerate() {
            *byte = Self::decode_byte(*byte, key[(i + offset) % key.len()]);
        }
    }

    // Decode data for unicode stream (1024 byte blocks)
    fn decode_data_ustrm(data: &mut [u8], offset: usize, key: &[u8]) {
        if key.is_empty() {
            return;
        }

        let mut decoded_len = 0;
        while decoded_len < data.len() {
            let decode_start = (decoded_len + offset) % 1024;
            let task_len = std::cmp::min(1024 - decode_start, data.len() - decoded_len);

            // Decode this chunk
            Self::decode_data(
                &mut data[decoded_len..decoded_len + task_len],
                decode_start % key.len(),
                key,
            );

            decoded_len += task_len;
        }
    }

    fn detect_install_location(file_names: &[String], setup_ini: Option<&str>) -> Option<String> {
        // First try to parse Setup.ini if available
        if let Some(ini_content) = setup_ini {
            // Look for install directory in Setup.ini
            // Common keys: "InstallDir=", "TargetDir=", "DefaultDir="
            for line in ini_content.lines() {
                let line = line.trim();
                if let Some(value) = line
                    .strip_prefix("InstallDir=")
                    .or_else(|| line.strip_prefix("TargetDir="))
                    .or_else(|| line.strip_prefix("DefaultDir="))
                    .or_else(|| line.strip_prefix("INSTALLDIR="))
                {
                    return Some(value.trim().to_string());
                }
            }
        }

        // Check for common data files
        let _has_data_cab = file_names
            .iter()
            .any(|f| f.to_lowercase().starts_with("data") && f.ends_with(".cab"));
        let _has_setup_ini = file_names
            .iter()
            .any(|f| f.eq_ignore_ascii_case("setup.ini"));

        // InstallShield installers typically install to Program Files
        // Return None as we cannot determine the exact path without more info
        None
    }

    fn parse_setup_ini_metadata(
        ini_content: &str,
    ) -> (
        Option<String>,
        Option<String>,
        Option<String>,
        Option<u16>,
        Option<String>,
    ) {
        let mut product_name = None;
        let mut product_version = None;
        let mut product_code = None;
        let mut default_language = None;
        let mut package_name = None;

        for line in ini_content.lines() {
            let line = line.trim();

            if let Some(value) = line.strip_prefix("Product=") {
                product_name = Some(value.trim().to_string());
            } else if let Some(value) = line.strip_prefix("ProductVersion=") {
                product_version = Some(value.trim().to_string());
            } else if let Some(value) = line.strip_prefix("ProductCode=") {
                product_code = Some(value.trim().to_string());
            } else if let Some(value) = line.strip_prefix("Default=") {
                // Parse hex language code like "0x0409"
                if let Some(hex_str) = value.trim().strip_prefix("0x") {
                    default_language = u16::from_str_radix(hex_str, 16).ok();
                }
            } else if let Some(value) = line.strip_prefix("PackageName=") {
                package_name = Some(value.trim().to_string());
            }
        }

        (
            product_name,
            product_version,
            product_code,
            default_language,
            package_name,
        )
    }
}

impl Installers for InstallShield {
    fn installers(&self) -> Vec<Installer> {
        use winget_types::installer::{AppsAndFeaturesEntries, AppsAndFeaturesEntry};

        // If we have an MSI, use its installers data and merge with InstallShield data
        if let Some(ref msi) = self.msi {
            let mut msi_installers = msi.installers();

            // Merge InstallShield metadata into MSI installers
            for installer in &mut msi_installers {
                // Prefer InstallShield's locale if available
                if installer.locale.is_none() {
                    installer.locale = self.primary_language.and_then(|lang_id| {
                        Language::from_code(lang_id)
                            .tag()
                            .parse::<LanguageTag>()
                            .ok()
                    });
                }

                // Override installer type to Exe since it's wrapped
                installer.r#type = Some(InstallerType::Exe);
            }

            return msi_installers;
        }

        // Otherwise, use InstallShield metadata
        // Determine scope based on architecture and typical InstallShield behavior
        // InstallShield installers typically require admin privileges and install to Program Files
        let scope = Some(Scope::Machine);

        let locale = self.primary_language.and_then(|lang_id| {
            Language::from_code(lang_id)
                .tag()
                .parse::<LanguageTag>()
                .ok()
        });

        let installer = Installer {
            locale,
            architecture: self.architecture,
            r#type: Some(InstallerType::Exe),
            scope,
            product_code: self.product_code.clone(),
            apps_and_features_entries: if self.product_name.is_some()
                || self.product_version.is_some()
                || self.product_code.is_some()
            {
                AppsAndFeaturesEntry::builder()
                    .maybe_display_name(self.product_name.as_deref())
                    .maybe_display_version(self.product_version.as_deref())
                    .maybe_product_code(self.product_code.as_deref())
                    .build()
                    .into()
            } else {
                AppsAndFeaturesEntries::new()
            },
            installation_metadata: InstallationMetadata {
                default_install_location: self
                    .install_location
                    .as_ref()
                    .map(|s| Utf8PathBuf::from(s)),
                ..InstallationMetadata::default()
            },

            ..Installer::default()
        };

        vec![installer]
    }
}
