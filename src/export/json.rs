//! JSON export file writing.

use std::path::Path;

use anyhow::Result;
use serde::Serialize;
use serde_json::json;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    TreeObjects,
    GroupMembers,
    ObjectGroups,
    SecurityDescriptor,
    Gpos,
    AdIntegratedDns,
}

impl ExportFormat {
    fn format_string(self) -> &'static str {
        match self {
            Self::TreeObjects => "tree_objects",
            Self::GroupMembers => "group_members",
            Self::ObjectGroups => "object_groups",
            Self::SecurityDescriptor => "security_descriptor",
            Self::Gpos => "gpos",
            Self::AdIntegratedDns => "adidns",
        }
    }

    fn suffix(self) -> &'static str {
        match self {
            Self::TreeObjects => "objects",
            Self::GroupMembers => "members",
            Self::ObjectGroups => "groups",
            Self::SecurityDescriptor => "sd",
            Self::Gpos => "gpos",
            Self::AdIntegratedDns => "dns",
        }
    }
}

/// Write `data` to `<exportdir>/<timestamp_ms>_<suffix>.json`.
pub fn export<T: Serialize>(
    exportdir: &str,
    format: ExportFormat,
    data: &T,
) -> Result<std::path::PathBuf> {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_millis();

    let filename = format!("{ts}_{}.json", format.suffix());
    let path = Path::new(exportdir).join(&filename);

    std::fs::create_dir_all(exportdir)?;

    let payload = json!({
        "Data": data,
        "Format": format.format_string(),
    });

    let content = serde_json::to_string_pretty(&payload)?;
    std::fs::write(&path, content)?;

    Ok(path)
}
