//! DNS record (dnsRecord) binary parsing per MS-DNSP.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum RecordError {
    #[error("record buffer too short")]
    TooShort,
    #[error("unsupported record type: {0}")]
    UnsupportedType(u16),
}

#[derive(Debug, Clone)]
pub struct DnsRecord {
    pub record_type: RecordType,
    pub ttl: u32,
    pub timestamp: u32,
    pub data: RecordData,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordType {
    A,
    Aaaa,
    Ns,
    Cname,
    Soa,
    Ptr,
    Mx,
    Srv,
    Txt,
    Other(u16),
}

#[derive(Debug, Clone)]
pub enum RecordData {
    A(std::net::Ipv4Addr),
    Aaaa(std::net::Ipv6Addr),
    Name(String),
    Mx {
        priority: u16,
        exchange: String,
    },
    Srv {
        priority: u16,
        weight: u16,
        port: u16,
        target: String,
    },
    Txt(Vec<String>),
    Soa {
        mname: String,
        rname: String,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    },
    Raw(Vec<u8>),
}

impl DnsRecord {
    /// Parse a single DNS record from its binary `dnsRecord` attribute value.
    pub fn parse(bytes: &[u8]) -> Result<Self, RecordError> {
        todo!(
            "parse DNS_RPC_RECORD: DataLength(2) + Type(2) + Version(1) + Rank(1) + \
             Flags(2) + Serial(4) + TtlSeconds(4) + Reserved(4) + TimeStamp(4) + Data"
        )
    }
}
