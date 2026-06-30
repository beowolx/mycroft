use serde_json::Value;

use crate::schema::{CURRENT_MANIFEST_VERSION, Manifest};

#[derive(Debug, thiserror::Error)]
pub enum MigrationError {
  #[error("manifest is not a JSON object")]
  NotObject,
  #[error("manifest is missing the required `manifest_version` field")]
  MissingVersion,
  #[error("manifest_version {found} is newer than supported version {max}")]
  TooNew { found: u64, max: u32 },
  #[error("failed to deserialize manifest: {0}")]
  Deserialize(#[from] serde_json::Error),
}

/// Migrates raw manifest JSON to the current manifest structure.
///
/// # Errors
///
/// Returns an error when the JSON is not an object, has no manifest version,
/// declares a newer version than this crate supports, or cannot deserialize into
/// the current schema.
pub fn migrate_to_current(raw: Value) -> Result<Manifest, MigrationError> {
  let object = raw.as_object().ok_or(MigrationError::NotObject)?;
  let version = object
    .get("manifest_version")
    .and_then(Value::as_u64)
    .ok_or(MigrationError::MissingVersion)?;

  if version > u64::from(CURRENT_MANIFEST_VERSION) {
    return Err(MigrationError::TooNew {
      found: version,
      max: CURRENT_MANIFEST_VERSION,
    });
  }

  let manifest = serde_json::from_value(raw)?;
  Ok(manifest)
}
