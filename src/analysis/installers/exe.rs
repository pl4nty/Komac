use std::io::{Read, Seek};

use color_eyre::Result;
use inno::{Inno, error::InnoError};
use winget_types::installer::{Architecture, Installer, InstallerSwitches, InstallerType};
use yara_x::mods::PE;

use super::{super::Installers, Burn, Nsis};
use crate::{
    analysis::installers::{burn::BurnError, nsis::NsisError},
    traits::FromMachine,
};

const ORIGINAL_FILENAME: &str = "OriginalFilename";
const INTERNAL_NAME: &str = "InternalName";
const FILE_DESCRIPTION: &str = "FileDescription";
const BASIC_INSTALLER_KEYWORDS: [&str; 2] = ["installer", "setup"];

pub enum Exe {
    Burn(Box<Burn>),
    Inno(Box<Inno>),
    Nsis(Nsis),
    Generic(Box<Installer>),
}

impl Exe {
    pub fn new<R: Read + Seek>(mut reader: R, pe: &PE) -> Result<Self> {
        match Burn::new(&mut reader, pe) {
            Ok(burn) => return Ok(Self::Burn(Box::new(burn))),
            Err(BurnError::NotBurnFile) => {}
            Err(error) => return Err(error.into()),
        }

        match Inno::new(&mut reader) {
            Ok(inno) => return Ok(Self::Inno(Box::new(inno))),
            Err(InnoError::NotInnoFile) => {}
            Err(error) => return Err(error.into()),
        }

        match Nsis::new(&mut reader, pe) {
            Ok(nsis) => return Ok(Self::Nsis(nsis)),
            Err(NsisError::NotNsisFile) => {}
            Err(error) => return Err(error.into()),
        }

        let internal_name = pe
            .version_info_list
            .iter()
            .find(|key_value| key_value.key() == INTERNAL_NAME)
            .and_then(|key_value| key_value.value.as_deref())
            .map(str::to_ascii_lowercase)
            .unwrap_or_default();

        let switches = match internal_name.as_str() {
            "sfxcab.exe" => InstallerSwitches::builder()
                .silent("/quiet".parse().unwrap())
                .build(),
            "7zs.sfx" | "7z.sfx" | "7zsd.sfx" => InstallerSwitches::builder()
                .silent("/s".parse().unwrap())
                .build(),
            "setup launcher" => InstallerSwitches::builder()
                .silent("/s".parse().unwrap())
                .build(),
            "wextract" => InstallerSwitches::builder()
                .silent("/Q".parse().unwrap())
                .build(),
            _ => InstallerSwitches::default(),
        };

        let installer_type = if switches.silent().is_some() {
            InstallerType::Exe
        } else {
            let is_installer = pe
                .version_info_list
                .iter()
                .filter(|key_value| matches!(key_value.key(), FILE_DESCRIPTION | ORIGINAL_FILENAME))
                .filter_map(|key_value| key_value.value.as_deref().map(str::to_ascii_lowercase))
                .any(|value| {
                    BASIC_INSTALLER_KEYWORDS
                        .iter()
                        .any(|keyword| value.contains(keyword))
                });

            if is_installer {
                InstallerType::Exe
            } else {
                InstallerType::Portable
            }
        };

        Ok(Self::Generic(Box::new(Installer {
            architecture: Architecture::from_machine(pe.machine()),
            r#type: Some(installer_type),
            switches,
            ..Installer::default()
        })))
    }
}

impl Installers for Exe {
    fn installers(&self) -> Vec<Installer> {
        match self {
            Self::Burn(burn) => burn.installers(),
            Self::Inno(inno) => inno.installers(),
            Self::Nsis(nsis) => nsis.installers(),
            Self::Generic(installer) => vec![*installer.clone()],
        }
    }
}
