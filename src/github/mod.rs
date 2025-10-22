pub mod client;
mod error;
pub mod graphql;
mod rest;
pub mod utils;

use const_format::formatcp;
pub use error::GitHubError;

pub const MICROSOFT: &str = "microsoft";
pub const WINGET_PKGS: &str = "winget-pkgs";
pub const WINGET_PKGS_FULL_NAME: &str = "pl4nty/winget-pkgs-selfhost";
pub const GITHUB_HOST: &str = "github.com";
