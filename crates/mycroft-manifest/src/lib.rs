pub mod addr;
pub mod import_catalog;
pub mod load;
pub mod migrate;
pub mod schema;
pub mod template;
pub mod validate;

pub use load::{
  ManifestLoadError, load_manifest_path, parse_manifest_bytes,
  parse_manifest_str,
};
pub use schema::{
  CURRENT_MANIFEST_VERSION, ControlMode, DetectionSpec, EvidenceOutcome,
  HttpMethod, Manifest, ManifestDefaults, MatchOp, RedirectMode,
  RedirectPolicy, RequestSpec, SignalKind, SignalSpec, Site, SiteId,
  StatusMatch, UsernameEncoding, UsernameRules,
};
pub use validate::{
  ManifestValidationError, SiteValidationError, validate_manifest,
  validate_site,
};

pub const BUNDLED_MANIFEST_JSON: &str =
  include_str!("../../../manifests/sites.v1.json");

/// Loads the manifest bundled into this crate.
///
/// # Errors
///
/// Returns an error if the bundled manifest cannot be migrated or validated.
pub fn bundled_manifest() -> Result<Manifest, ManifestLoadError> {
  parse_manifest_str(BUNDLED_MANIFEST_JSON)
}
