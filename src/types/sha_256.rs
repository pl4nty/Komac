use std::str::FromStr;

use color_eyre::eyre::eyre;
use color_eyre::Result;
use heapless::String;
use serde::{Deserialize, Serialize};

// 256 bits / 4 bits per character
const SHA256_LEN: usize = 256 / 4;

#[derive(Clone, Debug, Default, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct Sha256String(String<SHA256_LEN>);

impl Sha256String {
    pub fn from_hasher(data: &[u8]) -> Result<Self> {
        let mut encode_buf = [0; SHA256_LEN];
        let sha_256 = base16ct::upper::encode_str(&data, &mut encode_buf)?;
        Ok(Self(String::<SHA256_LEN>::from_str(sha_256).map_err(
            |_| eyre!("SHA256 must be {SHA256_LEN} bytes long"),
        )?))
    }
}
