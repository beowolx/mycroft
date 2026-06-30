use std::path::Path;

use crate::migrate::{MigrationError, migrate_to_current};
use crate::schema::Manifest;
use crate::validate::{ManifestValidationError, validate_manifest};

#[derive(Debug, thiserror::Error)]
pub enum ManifestLoadError {
  #[error("failed to read manifest '{path}': {source}")]
  Io {
    path: String,
    #[source]
    source: std::io::Error,
  },
  #[error("manifest is not valid JSON: {0}")]
  Json(#[from] serde_json::Error),
  #[error(transparent)]
  Migration(#[from] MigrationError),
  #[error(transparent)]
  Validation(#[from] ManifestValidationError),
}

/// Parses, migrates, and validates a manifest from a JSON string.
///
/// # Errors
///
/// Returns an error when the input is not valid JSON, cannot be migrated to the
/// current manifest version, or fails manifest validation.
pub fn parse_manifest_str(json: &str) -> Result<Manifest, ManifestLoadError> {
  let value = serde_json::from_str(json)?;
  let manifest = migrate_to_current(value)?;
  validate_manifest(&manifest)?;
  Ok(manifest)
}

/// Parses, migrates, and validates a manifest from JSON bytes.
///
/// # Errors
///
/// Returns an error when the input is not valid JSON, cannot be migrated to the
/// current manifest version, or fails manifest validation.
pub fn parse_manifest_bytes(
  bytes: &[u8],
) -> Result<Manifest, ManifestLoadError> {
  let value = serde_json::from_slice(bytes)?;
  let manifest = migrate_to_current(value)?;
  validate_manifest(&manifest)?;
  Ok(manifest)
}

/// Loads, parses, migrates, and validates a manifest file.
///
/// # Errors
///
/// Returns an error when the file cannot be read, the bytes are not valid JSON,
/// the manifest cannot be migrated, or validation fails.
pub fn load_manifest_path(path: &Path) -> Result<Manifest, ManifestLoadError> {
  let bytes = std::fs::read(path).map_err(|source| ManifestLoadError::Io {
    path: path.display().to_string(),
    source,
  })?;
  parse_manifest_bytes(&bytes)
}
