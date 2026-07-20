//! MS-DTYP security descriptor binary parsing, SID conversion, and well-known SID table.

pub mod ace;
pub mod descriptor;
pub mod sid;

pub use descriptor::SecurityDescriptor;
pub use sid::Sid;
