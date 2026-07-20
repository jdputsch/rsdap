//! SID binary parsing, string formatting, and well-known SID table.

use std::fmt;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum SidError {
    #[error("SID buffer too short")]
    TooShort,
    #[error("invalid SID revision: {0}")]
    InvalidRevision(u8),
}

/// A Windows Security Identifier (SID).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Sid {
    pub revision: u8,
    pub identifier_authority: [u8; 6],
    pub sub_authorities: Vec<u32>,
}

impl Sid {
    /// Parse a SID from its binary representation.
    pub fn parse(bytes: &[u8]) -> Result<(Self, usize), SidError> {
        todo!(
            "parse: revision(1) + sub_authority_count(1) + identifier_authority(6) \
             + sub_authority_count * u32_le, return (Sid, bytes_consumed)"
        )
    }

    /// Return the well-known name for this SID, if one exists.
    pub fn well_known_name(&self) -> Option<&'static str> {
        WELL_KNOWN_SIDS
            .iter()
            .find(|(s, _)| s == &self.to_string().as_str())
            .map(|(_, n)| *n)
    }
}

impl fmt::Display for Sid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let authority = {
            let a = &self.identifier_authority;
            if a[0] == 0 && a[1] == 0 {
                u32::from_be_bytes([a[2], a[3], a[4], a[5]]) as u64
            } else {
                u64::from_be_bytes([0, 0, a[0], a[1], a[2], a[3], a[4], a[5]])
            }
        };
        write!(f, "S-{}-{}", self.revision, authority)?;
        for sub in &self.sub_authorities {
            write!(f, "-{sub}")?;
        }
        Ok(())
    }
}

/// A static table of well-known SIDs mapping string form → human-readable name.
static WELL_KNOWN_SIDS: &[(&str, &str)] = &[
    ("S-1-0-0", "Null SID"),
    ("S-1-1-0", "Everyone"),
    ("S-1-2-0", "Local"),
    ("S-1-3-0", "Creator Owner"),
    ("S-1-3-1", "Creator Group"),
    ("S-1-5-2", "Network"),
    ("S-1-5-4", "Interactive"),
    ("S-1-5-6", "Service"),
    ("S-1-5-7", "Anonymous"),
    ("S-1-5-9", "Enterprise Domain Controllers"),
    ("S-1-5-10", "Self"),
    ("S-1-5-11", "Authenticated Users"),
    ("S-1-5-12", "Restricted Code"),
    ("S-1-5-13", "Terminal Server User"),
    ("S-1-5-14", "Remote Interactive Logon"),
    ("S-1-5-17", "IUSR"),
    ("S-1-5-18", "SYSTEM"),
    ("S-1-5-19", "Local Service"),
    ("S-1-5-20", "Network Service"),
    ("S-1-5-32-544", "Administrators"),
    ("S-1-5-32-545", "Users"),
    ("S-1-5-32-546", "Guests"),
    ("S-1-5-32-547", "Power Users"),
    ("S-1-5-32-548", "Account Operators"),
    ("S-1-5-32-549", "Server Operators"),
    ("S-1-5-32-550", "Print Operators"),
    ("S-1-5-32-551", "Backup Operators"),
    ("S-1-5-32-552", "Replicators"),
    ("S-1-5-32-554", "Pre-Windows 2000 Compatible Access"),
    ("S-1-5-32-555", "Remote Desktop Users"),
    ("S-1-5-32-556", "Network Configuration Operators"),
    ("S-1-5-32-557", "Incoming Forest Trust Builders"),
    ("S-1-5-32-558", "Performance Monitor Users"),
    ("S-1-5-32-559", "Performance Log Users"),
    ("S-1-5-32-560", "Windows Authorization Access Group"),
    ("S-1-5-32-561", "Terminal Server License Servers"),
    ("S-1-5-32-562", "Distributed COM Users"),
    ("S-1-5-32-568", "IIS_IUSRS"),
    ("S-1-5-32-569", "Cryptographic Operators"),
    ("S-1-5-32-573", "Event Log Readers"),
    ("S-1-5-32-574", "Certificate Service DCOM Access"),
    ("S-1-5-32-575", "RDS Remote Access Servers"),
    ("S-1-5-32-576", "RDS Endpoint Servers"),
    ("S-1-5-32-577", "RDS Management Servers"),
    ("S-1-5-32-578", "Hyper-V Administrators"),
    ("S-1-5-32-579", "Access Control Assistance Operators"),
    ("S-1-5-32-580", "Remote Management Users"),
    ("S-1-16-0", "Untrusted Mandatory Level"),
    ("S-1-16-4096", "Low Mandatory Level"),
    ("S-1-16-8192", "Medium Mandatory Level"),
    ("S-1-16-8448", "Medium Plus Mandatory Level"),
    ("S-1-16-12288", "High Mandatory Level"),
    ("S-1-16-16384", "System Mandatory Level"),
    ("S-1-16-20480", "Protected Process Mandatory Level"),
    ("S-1-16-28672", "Secure Process Mandatory Level"),
];
