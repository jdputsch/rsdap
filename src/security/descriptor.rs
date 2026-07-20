//! Security descriptor (SECURITY_DESCRIPTOR) binary parsing per MS-DTYP.

use thiserror::Error;

use super::ace::Ace;
use super::sid::Sid;

#[derive(Debug, Error)]
pub enum SdError {
    #[error("buffer too short for security descriptor header")]
    TooShort,
    #[error("invalid revision: {0}")]
    InvalidRevision(u8),
    #[error("ACL parse error at offset {offset}: {reason}")]
    AclParse { offset: usize, reason: String },
}

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ControlFlags: u16 {
        const SE_OWNER_DEFAULTED        = 0x0001;
        const SE_GROUP_DEFAULTED        = 0x0002;
        const SE_DACL_PRESENT           = 0x0004;
        const SE_DACL_DEFAULTED         = 0x0008;
        const SE_SACL_PRESENT           = 0x0010;
        const SE_SACL_DEFAULTED         = 0x0020;
        const SE_DACL_AUTO_INHERIT_REQ  = 0x0100;
        const SE_SACL_AUTO_INHERIT_REQ  = 0x0200;
        const SE_DACL_AUTO_INHERITED    = 0x0400;
        const SE_SACL_AUTO_INHERITED    = 0x0800;
        const SE_DACL_PROTECTED         = 0x1000;
        const SE_SACL_PROTECTED         = 0x2000;
        const SE_RM_CONTROL_VALID       = 0x4000;
        const SE_SELF_RELATIVE          = 0x8000;
    }
}

#[derive(Debug, Clone)]
pub struct SecurityDescriptor {
    pub revision: u8,
    pub control: ControlFlags,
    pub owner: Option<Sid>,
    pub group: Option<Sid>,
    pub dacl: Vec<Ace>,
    pub sacl: Vec<Ace>,
}

impl SecurityDescriptor {
    /// Parse a binary security descriptor (e.g. the `nTSecurityDescriptor` attribute value).
    pub fn parse(bytes: &[u8]) -> Result<Self, SdError> {
        todo!(
            "parse SECURITY_DESCRIPTOR_RELATIVE: \
             revision(1) + sbz1(1) + control(2) + offset_owner(4) + offset_group(4) + \
             offset_sacl(4) + offset_dacl(4), then parse ACLs at each offset"
        )
    }

    /// Serialize back to binary form.
    pub fn to_bytes(&self) -> Vec<u8> {
        todo!("serialize SD to SECURITY_DESCRIPTOR_RELATIVE binary format")
    }
}
