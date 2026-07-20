//! Authentication helpers: simple bind, NTLM, Kerberos, certificate.

use ldap3::Ldap;

use crate::config::AuthMethod;
use crate::ldap::connection::LdapError;

/// Perform the appropriate bind on an established LDAP connection.
pub async fn bind(ldap: &mut Ldap, method: &AuthMethod) -> Result<(), LdapError> {
    match method {
        AuthMethod::Anonymous => Ok(()),
        AuthMethod::Simple { username, password } => simple_bind(ldap, username, password).await,
        AuthMethod::Ntlm { .. } => {
            todo!("NTLM SASL bind — Phase 9")
        }
        AuthMethod::Kerberos { .. } => {
            todo!("Kerberos GSSAPI bind — Phase 9")
        }
        AuthMethod::Certificate { .. } | AuthMethod::CertificatePkcs12 { .. } => {
            // Certificate auth is handled at TLS handshake time in the connection
            // settings; no explicit bind step is needed for SASL EXTERNAL.
            Ok(())
        }
    }
}

async fn simple_bind(ldap: &mut Ldap, username: &str, password: &str) -> Result<(), LdapError> {
    let res = ldap.simple_bind(username, password).await?;
    if res.success().is_err() {
        return Err(LdapError::AuthFailed);
    }
    Ok(())
}
