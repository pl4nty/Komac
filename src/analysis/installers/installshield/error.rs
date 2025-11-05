use std::fmt;

#[derive(Debug)]
pub enum InstallShieldError {
    NotInstallShieldFile,
    InvalidHeader,
    IoError(std::io::Error),
    Utf8Error(std::string::FromUtf8Error),
}

impl fmt::Display for InstallShieldError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotInstallShieldFile => write!(f, "Not an InstallShield file"),
            Self::InvalidHeader => write!(f, "Invalid InstallShield header"),
            Self::IoError(e) => write!(f, "IO error: {}", e),
            Self::Utf8Error(e) => write!(f, "UTF-8 error: {}", e),
        }
    }
}

impl std::error::Error for InstallShieldError {}

impl From<std::io::Error> for InstallShieldError {
    fn from(err: std::io::Error) -> Self {
        Self::IoError(err)
    }
}

impl From<std::string::FromUtf8Error> for InstallShieldError {
    fn from(err: std::string::FromUtf8Error) -> Self {
        Self::Utf8Error(err)
    }
}
