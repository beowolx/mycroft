use std::collections::HashSet;

use url::Url;

use crate::addr::host_literal_is_disallowed;
use crate::schema::{
  BlockSignal, CURRENT_MANIFEST_VERSION, ExtractSource, Manifest, MatchOp,
  RequestSpec, SignalKind, SignalKindSpec, SignalSpec, Site, SubjectKind,
};
use crate::template;

const DENIED_HEADERS: &[&str] =
  &["content-length", "connection", "transfer-encoding"];

#[derive(Debug, thiserror::Error)]
pub enum ManifestValidationError {
  #[error("unsupported manifest_version {found}; expected {expected}")]
  UnsupportedVersion { found: u32, expected: u32 },
  #[error("manifest contains no sites")]
  NoSites,
  #[error("duplicate site id '{0}'")]
  DuplicateSiteId(String),
  #[error("default block signal '{id}' is invalid: {reason}")]
  DefaultBlockSignal { id: String, reason: String },
  #[error("site '{site}': {source}")]
  Site {
    site: String,
    #[source]
    source: SiteValidationError,
  },
}

#[derive(Debug, thiserror::Error)]
pub enum SiteValidationError {
  #[error("empty site id")]
  EmptyId,
  #[error("invalid url_main '{0}'")]
  InvalidUrlMain(String),
  #[error("profile_url_template is missing the '{{username}}' placeholder")]
  MissingPlaceholder,
  #[error("site supports email but no template uses an email placeholder")]
  MissingEmailPlaceholder,
  #[error("site declares no supported subject kinds")]
  NoSupportedSubjects,
  #[error("template '{template}' is not a valid URL: {reason}")]
  InvalidTemplate { template: String, reason: String },
  #[error("template '{template}' uses unsupported scheme '{scheme}'")]
  UnsupportedScheme { template: String, scheme: String },
  #[error("template '{template}' targets disallowed host '{host}'")]
  DisallowedHost { template: String, host: String },
  #[error("invalid regex '{regex}': {reason}")]
  InvalidRegex { regex: String, reason: String },
  #[error("no detection signals defined")]
  NoSignals,
  #[error("duplicate signal id '{0}'")]
  DuplicateSignalId(String),
  #[error("signal '{id}' is invalid: {reason}")]
  Signal { id: String, reason: String },
  #[error("signal '{id}' weight {weight} is out of range [0.0, 1.0]")]
  WeightOutOfRange { id: String, weight: f32 },
  #[error("threshold {0} is out of range [0.0, 1.0]")]
  ThresholdOutOfRange(f32),
  #[error("disallowed header '{0}'")]
  DisallowedHeader(String),
  #[error("header '{name}' has an invalid value")]
  InvalidHeaderValue { name: String },
  #[error(
    "requires_control is set but no absent_username or absent_template exists"
  )]
  MissingControlSource,
}

/// Validates a complete manifest.
///
/// # Errors
///
/// Returns an error when the manifest version is unsupported, the manifest has
/// no sites, site IDs collide, default block signals are invalid, or any site is
/// invalid.
pub fn validate_manifest(
  manifest: &Manifest,
) -> Result<(), ManifestValidationError> {
  if manifest.manifest_version != CURRENT_MANIFEST_VERSION {
    return Err(ManifestValidationError::UnsupportedVersion {
      found: manifest.manifest_version,
      expected: CURRENT_MANIFEST_VERSION,
    });
  }
  if manifest.sites.is_empty() {
    return Err(ManifestValidationError::NoSites);
  }

  for block in &manifest.defaults.block_signals {
    validate_block_signal(block).map_err(|reason| {
      ManifestValidationError::DefaultBlockSignal {
        id: block.id.clone(),
        reason,
      }
    })?;
  }

  let mut seen_ids = HashSet::new();
  for site in &manifest.sites {
    if !seen_ids.insert(site.id.as_str()) {
      return Err(ManifestValidationError::DuplicateSiteId(site.id.clone()));
    }
    validate_site(site).map_err(|source| ManifestValidationError::Site {
      site: site.id.clone(),
      source,
    })?;
  }
  Ok(())
}

/// Validates a single manifest site.
///
/// # Errors
///
/// Returns an error when identifiers, templates, username rules, requests,
/// detection signals, thresholds, headers, or required controls are invalid.
pub fn validate_site(site: &Site) -> Result<(), SiteValidationError> {
  if site.id.trim().is_empty() {
    return Err(SiteValidationError::EmptyId);
  }

  Url::parse(&site.url_main)
    .map_err(|_| SiteValidationError::InvalidUrlMain(site.url_main.clone()))?;

  if let Some(regex) = &site.username.regex {
    compile_regex(regex)?;
  }

  validate_template(&site.profile_url_template)?;
  if let Some(probe) = &site.request.url_template {
    validate_template(probe)?;
  }
  if let Some(pre) = &site.prerequest {
    validate_template(&pre.url_template)?;
    for extraction in &pre.extract {
      if let ExtractSource::Regex { pattern } = &extraction.from {
        compile_regex(pattern)?;
      }
    }
  }

  if site.supports.is_empty() {
    return Err(SiteValidationError::NoSupportedSubjects);
  }
  if site.supports_kind(SubjectKind::Username) && !site_has_placeholder(site) {
    return Err(SiteValidationError::MissingPlaceholder);
  }
  if site.supports_kind(SubjectKind::Email)
    && !site_has_any_email_placeholder(site)
  {
    return Err(SiteValidationError::MissingEmailPlaceholder);
  }

  validate_request(&site.request)?;
  validate_signals(site)?;

  validate_threshold(site.detection.min_hit_score)?;
  validate_threshold(site.detection.min_miss_score)?;
  validate_threshold(site.detection.decision_margin)?;

  validate_control_source(site)?;

  Ok(())
}

fn validate_signals(site: &Site) -> Result<(), SiteValidationError> {
  if site.detection.signals.is_empty() {
    return Err(SiteValidationError::NoSignals);
  }

  let mut signal_ids = HashSet::new();
  for signal in &site.detection.signals {
    if !signal_ids.insert(signal.id.as_str()) {
      return Err(SiteValidationError::DuplicateSignalId(signal.id.clone()));
    }
    if !(0.0..=1.0).contains(&signal.weight) {
      return Err(SiteValidationError::WeightOutOfRange {
        id: signal.id.clone(),
        weight: signal.weight,
      });
    }
    validate_signal(signal).map_err(|reason| SiteValidationError::Signal {
      id: signal.id.clone(),
      reason,
    })?;
  }

  for block in &site.detection.block_signals {
    validate_block_signal(block).map_err(|reason| {
      SiteValidationError::Signal {
        id: block.id.clone(),
        reason,
      }
    })?;
  }

  Ok(())
}

fn validate_control_source(site: &Site) -> Result<(), SiteValidationError> {
  if !site.risk.as_ref().is_some_and(|r| r.requires_control) {
    return Ok(());
  }
  if site.username.absent_template.is_some() {
    return Ok(());
  }
  if site
    .detection
    .control
    .as_ref()
    .is_some_and(|c| c.absent_username.is_some())
  {
    return Ok(());
  }
  if site
    .known_controls
    .as_ref()
    .is_some_and(|c| !c.absent.is_empty())
  {
    return Ok(());
  }
  Err(SiteValidationError::MissingControlSource)
}

fn validate_threshold(value: Option<f32>) -> Result<(), SiteValidationError> {
  match value {
    Some(v) if !(0.0..=1.0).contains(&v) => {
      Err(SiteValidationError::ThresholdOutOfRange(v))
    }
    _ => Ok(()),
  }
}

fn validate_request(request: &RequestSpec) -> Result<(), SiteValidationError> {
  for (name, value) in &request.headers {
    let lower = name.to_ascii_lowercase();
    if DENIED_HEADERS.contains(&lower.as_str()) || lower.starts_with("proxy-") {
      return Err(SiteValidationError::DisallowedHeader(name.clone()));
    }
    if name.bytes().any(|b| b < 0x20 || b == 0x7f)
      || value.bytes().any(|b| b < 0x20 && b != b'\t')
    {
      return Err(SiteValidationError::InvalidHeaderValue {
        name: name.clone(),
      });
    }
  }
  Ok(())
}

fn site_has_placeholder(site: &Site) -> bool {
  site_template_matches(site, &template::has_placeholder)
}

fn site_has_any_email_placeholder(site: &Site) -> bool {
  site_template_matches(site, &template::has_email_placeholder)
}

fn site_template_matches(site: &Site, pred: &impl Fn(&str) -> bool) -> bool {
  pred(&site.profile_url_template)
    || site.request.url_template.as_deref().is_some_and(pred)
    || site.request.headers.values().any(|v| pred(v))
    || site.request.body_form.values().any(|v| pred(v))
    || site
      .request
      .body_template
      .as_ref()
      .is_some_and(|b| json_template_matches(b, pred))
}

fn json_template_matches(
  value: &serde_json::Value,
  pred: &impl Fn(&str) -> bool,
) -> bool {
  match value {
    serde_json::Value::String(s) => pred(s),
    serde_json::Value::Array(items) => {
      items.iter().any(|v| json_template_matches(v, pred))
    }
    serde_json::Value::Object(map) => {
      map.values().any(|v| json_template_matches(v, pred))
    }
    _ => false,
  }
}

fn validate_template(tmpl: &str) -> Result<(), SiteValidationError> {
  let interpolated = template::interpolate_probe(tmpl);
  let url = Url::parse(&interpolated).map_err(|e| {
    SiteValidationError::InvalidTemplate {
      template: tmpl.to_string(),
      reason: e.to_string(),
    }
  })?;
  if url.scheme() != "https" && url.scheme() != "http" {
    return Err(SiteValidationError::UnsupportedScheme {
      template: tmpl.to_string(),
      scheme: url.scheme().to_string(),
    });
  }
  match url.host_str() {
    None => Err(SiteValidationError::InvalidTemplate {
      template: tmpl.to_string(),
      reason: "missing host".to_string(),
    }),
    Some(host) if host_literal_is_disallowed(host) => {
      Err(SiteValidationError::DisallowedHost {
        template: tmpl.to_string(),
        host: host.to_string(),
      })
    }
    Some(_) => Ok(()),
  }
}

fn compile_regex(pattern: &str) -> Result<(), SiteValidationError> {
  fancy_regex::Regex::new(pattern).map(|_| ()).map_err(|e| {
    SiteValidationError::InvalidRegex {
      regex: pattern.to_string(),
      reason: e.to_string(),
    }
  })
}

fn validate_signal(signal: &SignalSpec) -> Result<(), String> {
  match &signal.kind {
    SignalKindSpec::Status { match_spec } => {
      if match_spec.codes.is_empty() && match_spec.ranges.is_empty() {
        Err(
          "status signal requires `match.codes` or `match.ranges`".to_string(),
        )
      } else {
        Ok(())
      }
    }
    SignalKindSpec::Header {
      op, value, pattern, ..
    }
    | SignalKindSpec::Redirect { op, value, pattern }
    | SignalKindSpec::HtmlTitle { op, value, pattern }
    | SignalKindSpec::CssSelector {
      op, value, pattern, ..
    }
    | SignalKindSpec::JsonPath {
      op, value, pattern, ..
    } => validate_op_operand(*op, value.as_ref(), pattern.as_deref()),
    SignalKindSpec::BodyRegex { pattern } => compile_pattern(pattern),
    SignalKindSpec::CanonicalUrl { selector, pattern } => {
      if selector.is_some() {
        Ok(())
      } else {
        pattern.as_deref().map_or_else(
          || Err("canonical_url requires `selector` or `pattern`".to_string()),
          compile_pattern,
        )
      }
    }
    SignalKindSpec::BodySubstring { .. }
    | SignalKindSpec::UsernameEcho { .. }
    | SignalKindSpec::BodySimilarity { .. }
    | SignalKindSpec::BodySize { .. } => Ok(()),
  }
}

fn validate_op_operand(
  op: MatchOp,
  value: Option<&serde_json::Value>,
  pattern: Option<&str>,
) -> Result<(), String> {
  match op {
    MatchOp::Exists | MatchOp::EqualsUsername | MatchOp::ContainsUsername => {
      Ok(())
    }
    MatchOp::Regex => pattern.map_or_else(
      || Err("regex operator requires `pattern`".to_string()),
      compile_pattern,
    ),
    MatchOp::Equals | MatchOp::NotEquals | MatchOp::Contains => {
      require(value.is_some(), "operator requires a `value`")
    }
  }
}

fn compile_pattern(pattern: &str) -> Result<(), String> {
  regex::Regex::new(pattern)
    .map(|_| ())
    .map_err(|e| format!("invalid regex: {e}"))
}

fn validate_block_signal(signal: &BlockSignal) -> Result<(), String> {
  match signal.kind {
    SignalKind::Status => match &signal.match_spec {
      Some(m) if !m.codes.is_empty() || !m.ranges.is_empty() => Ok(()),
      _ => Err("status block signal requires `match`".to_string()),
    },
    SignalKind::BodyRegex => signal.pattern.as_deref().map_or_else(
      || Err("body_regex block signal requires `pattern`".to_string()),
      |p| {
        regex::Regex::new(p)
          .map(|_| ())
          .map_err(|e| format!("invalid regex: {e}"))
      },
    ),
    SignalKind::BodySubstring => require(
      signal.value.is_some(),
      "body_substring block signal requires `value`",
    ),
    SignalKind::Header => require(
      signal.header.is_some(),
      "header block signal requires `header`",
    ),
    other => Err(format!("unsupported block signal kind {other:?}")),
  }
}

fn require(condition: bool, message: &str) -> Result<(), String> {
  if condition {
    Ok(())
  } else {
    Err(message.to_string())
  }
}
