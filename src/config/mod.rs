//! CLI flag parsing, YAML config loading, and connection parameter resolution.

pub mod cli;
pub mod file;
pub mod types;

pub use types::*;

use anyhow::Result;

/// Merge CLI args and file config into a single resolved configuration.
pub fn resolve(args: cli::Cli, file: Option<file::FileConfig>) -> Result<ResolvedConfig> {
    todo!("merge CLI args and file config into ResolvedConfig")
}
