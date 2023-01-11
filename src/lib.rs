mod store;

use serde::{Deserialize, Serialize};
use std::{num::ParseIntError, time::Duration};

pub use store::{Record, RecordStore};

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Claims {
    /// List of origins from which update requests are allowed
    pub allowed_origins: Vec<String>,

    /// Root domain for which the token authorises
    pub domain: String,

    /// Subdomain of the root domain on which updates may be performed
    pub subdomain: String,

    /// Value to use for the username field
    pub username: String,
}

/// Parses a Duration from a string containing seconds.
/// Useful for command line parsing
pub fn parse_seconds(src: &str) -> Result<Duration, ParseIntError> {
    let seconds = src.parse::<u64>()?;
    Ok(Duration::from_secs(seconds))
}
