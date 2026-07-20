//! DNS zone discovery and dNSProperty parsing.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum DnsError {
    #[error("LDAP error: {0}")]
    Ldap(#[from] ldap3::LdapError),
    #[error("property parse error: {0}")]
    Parse(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ZoneScope {
    Domain,
    Forest,
}

#[derive(Debug, Clone)]
pub struct DnsZone {
    pub dn: String,
    pub name: String,
    pub scope: ZoneScope,
    pub properties: Vec<ZoneProperty>,
}

#[derive(Debug, Clone)]
pub struct ZoneProperty {
    pub id: u32,
    pub name: String,
    pub value: String,
}

/// Query both DomainDnsZones and ForestDnsZones for DNS zones.
pub async fn discover_zones(
    ldap: &mut ldap3::Ldap,
    root_dn: &str,
) -> Result<Vec<DnsZone>, DnsError> {
    todo!(
        "search CN=MicrosoftDNS,DC=DomainDnsZones,<root_dn> and \
         CN=MicrosoftDNS,DC=ForestDnsZones,<root_dn> for objectClass=dnsZone"
    )
}

/// Parse the binary `dNSProperty` attribute values for a zone.
pub fn parse_dns_properties(raw: &[&[u8]]) -> Vec<ZoneProperty> {
    todo!("parse each binary property value per MS-DNSP DNS_RPC_ZONE_INFO structure")
}
