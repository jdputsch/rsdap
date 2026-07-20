//! ACE (Access Control Entry) types and access mask interpretation per MS-DTYP.

use super::sid::Sid;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AceType {
    AccessAllowed,
    AccessDenied,
    AccessAllowedObject,
    AccessDeniedObject,
    Unknown(u8),
}

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct AceFlags: u8 {
        const OBJECT_INHERIT_ACE        = 0x01;
        const CONTAINER_INHERIT_ACE     = 0x02;
        const NO_PROPAGATE_INHERIT_ACE  = 0x04;
        const INHERIT_ONLY_ACE         = 0x08;
        const INHERITED_ACE            = 0x10;
        const SUCCESSFUL_ACCESS_ACE    = 0x40;
        const FAILED_ACCESS_ACE        = 0x80;
    }
}

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct AccessMask: u32 {
        // Generic
        const GENERIC_READ    = 0x80000000;
        const GENERIC_WRITE   = 0x40000000;
        const GENERIC_EXECUTE = 0x20000000;
        const GENERIC_ALL     = 0x10000000;
        // Standard
        const DELETE          = 0x00010000;
        const READ_CONTROL    = 0x00020000;
        const WRITE_DAC       = 0x00040000;
        const WRITE_OWNER     = 0x00080000;
        const SYNCHRONIZE     = 0x00100000;
        // DS-specific
        const DS_CREATE_CHILD  = 0x00000001;
        const DS_DELETE_CHILD  = 0x00000002;
        const DS_LIST_CONTENTS = 0x00000004;
        const DS_WRITE_PROP    = 0x00000008; // WRITE_PROPERTY (DS_WRITE_ATTRIBUTE)
        const DS_READ_PROP     = 0x00000010; // READ_PROPERTY (DS_READ_ATTRIBUTE)
        const DS_SELF          = 0x00000008;
        const DS_LIST_OBJECT   = 0x00000080;
        const DS_CONTROL_ACCESS = 0x00000100;
    }
}

#[derive(Debug, Clone)]
pub struct Ace {
    pub ace_type: AceType,
    pub flags: AceFlags,
    pub mask: AccessMask,
    pub sid: Sid,
    /// Present on object ACE types when the OBJ_TYPE_PRESENT flag is set.
    pub object_type: Option<[u8; 16]>,
    /// Present on object ACE types when the INHERITED_OBJ_TYPE_PRESENT flag is set.
    pub inherited_object_type: Option<[u8; 16]>,
}

impl Ace {
    /// Parse a single ACE from a byte slice, returning the ACE and bytes consumed.
    pub fn parse(bytes: &[u8]) -> Result<(Self, usize), super::descriptor::SdError> {
        todo!(
            "parse ACE header (type + flags + size), then dispatch to \
             parse_simple_ace or parse_object_ace based on type"
        )
    }
}
