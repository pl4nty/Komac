pub mod burn;
mod exe;
pub mod inno;
pub mod installshield;
mod msi;
pub mod msix_family;
pub mod nsis;
pub mod utils;
mod zip;

pub use burn::Burn;
pub use exe::Exe;
pub use installshield::InstallShield;
pub use msi::Msi;
pub use nsis::Nsis;
pub use zip::Zip;
