//! LDAP mutation operations: create, delete, move, modify, password reset.

use anyhow::Result;

use crate::ldap::connection::LdapError;

pub enum ObjectClass {
    OrganizationalUnit,
    Container,
    User,
    Group,
    Computer,
}

/// Create a new LDAP object under the given parent DN.
pub async fn create_object(
    ldap: &mut ldap3::Ldap,
    parent_dn: &str,
    rdn: &str,
    class: ObjectClass,
    extra_attrs: &[(&str, &[&str])],
) -> Result<(), LdapError> {
    todo!("ldap3 add operation with appropriate objectClass attributes")
}

/// Delete an LDAP object by DN.
pub async fn delete_object(ldap: &mut ldap3::Ldap, dn: &str) -> Result<(), LdapError> {
    todo!("ldap3 delete operation")
}

/// Move/rename an object: new RDN and/or new parent DN.
pub async fn move_object(
    ldap: &mut ldap3::Ldap,
    dn: &str,
    new_rdn: &str,
    new_parent: Option<&str>,
) -> Result<(), LdapError> {
    todo!("ldap3 modifyDN operation")
}

/// Replace all values of a single attribute.
pub async fn modify_attribute(
    ldap: &mut ldap3::Ldap,
    dn: &str,
    attr: &str,
    values: &[&str],
) -> Result<(), LdapError> {
    todo!("ldap3 modify replace operation")
}

/// Add a value to an attribute (or create the attribute).
pub async fn add_attribute_value(
    ldap: &mut ldap3::Ldap,
    dn: &str,
    attr: &str,
    value: &str,
) -> Result<(), LdapError> {
    todo!("ldap3 modify add operation")
}

/// Delete a specific attribute value, or the entire attribute if value is None.
pub async fn delete_attribute_value(
    ldap: &mut ldap3::Ldap,
    dn: &str,
    attr: &str,
    value: Option<&str>,
) -> Result<(), LdapError> {
    todo!("ldap3 modify delete operation")
}

/// Reset a user's password using `unicodePwd` replacement.
pub async fn reset_password(
    ldap: &mut ldap3::Ldap,
    dn: &str,
    new_password: &str,
) -> Result<(), LdapError> {
    todo!("encode new_password as UTF-16LE with quotes, replace unicodePwd")
}
