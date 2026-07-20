//! Authentication helpers: simple bind, NTLM, Kerberos, certificate.

use anyhow::Result;

use crate::config::AuthMethod;
use crate::ldap::connection::LdapError;

/// Perform the appropriate bind on an established LDAP connection.
pub async fn bind(ldap: &mut ldap3::Ldap, method: &AuthMethod) -> Result<(), LdapError> {
    todo!("dispatch to simple_bind, ntlm_bind, kerberos_bind, or cert_bind based on method")
}

async fn simple_bind(
    ldap: &mut ldap3::Ldap,
    username: &str,
    password: &str,
) -> Result<(), LdapError> {
    todo!("ldap3 simple bind")
}

async fn ntlm_bind(
    ldap: &mut ldap3::Ldap,
    domain: &str,
    username: &str,
    hash: &str,
) -> Result<(), LdapError> {
    todo!("NTLM SASL bind using SPNEGO/GSSAPI")
}

async fn kerberos_bind(
    ldap: &mut ldap3::Ldap,
    spn: Option<&str>,
    kdc: Option<&str>,
) -> Result<(), LdapError> {
    todo!("Kerberos GSSAPI bind reading from KRB5CCNAME")
}
