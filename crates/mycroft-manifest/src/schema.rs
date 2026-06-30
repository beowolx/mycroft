use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub const CURRENT_MANIFEST_VERSION: u32 = 1;

pub type SiteId = String;

const fn default_true() -> bool {
  true
}

#[expect(
  clippy::trivially_copy_pass_by_ref,
  reason = "serde skip_serializing_if callbacks receive references"
)]
const fn is_false(value: &bool) -> bool {
  !*value
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct Manifest {
  pub manifest_version: u32,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub schema: Option<String>,
  pub manifest_id: String,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub generated_at: Option<String>,
  #[serde(default)]
  pub defaults: ManifestDefaults,
  pub sites: Vec<Site>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct ManifestDefaults {
  pub timeout_ms: u64,
  pub connect_timeout_ms: u64,
  pub max_body_bytes: usize,
  pub redirect_policy: RedirectPolicy,
  pub control_mode: ControlMode,
  pub min_hit_score: f32,
  pub min_miss_score: f32,
  pub decision_margin: f32,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub user_agent: Option<String>,
  #[serde(skip_serializing_if = "Vec::is_empty")]
  pub block_signals: Vec<BlockSignal>,
}

impl Default for ManifestDefaults {
  fn default() -> Self {
    Self {
      timeout_ms: 12_000,
      connect_timeout_ms: 4_000,
      max_body_bytes: 262_144,
      redirect_policy: RedirectPolicy::default(),
      control_mode: ControlMode::Auto,
      min_hit_score: 0.72,
      min_miss_score: 0.72,
      decision_margin: 0.18,
      user_agent: None,
      block_signals: Vec::new(),
    }
  }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, JsonSchema)]
pub struct RedirectPolicy {
  pub mode: RedirectMode,
  pub max_hops: u32,
}

impl Default for RedirectPolicy {
  fn default() -> Self {
    Self {
      mode: RedirectMode::Follow,
      max_hops: 5,
    }
  }
}

#[derive(
  Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum RedirectMode {
  Follow,
  Manual,
}

#[derive(
  Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ControlMode {
  Off,
  #[default]
  Auto,
  Strict,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct Site {
  pub id: SiteId,
  pub name: String,
  pub url_main: String,
  #[serde(default = "default_true")]
  pub enabled: bool,
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub tags: Vec<String>,
  #[serde(default, skip_serializing_if = "is_false")]
  pub nsfw: bool,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub risk: Option<RiskInfo>,
  #[serde(default)]
  pub username: UsernameRules,
  pub profile_url_template: String,
  #[serde(default)]
  pub request: RequestSpec,
  pub detection: DetectionSpec,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub known_controls: Option<KnownControls>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
pub struct RiskInfo {
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub notes: Option<String>,
  #[serde(default, skip_serializing_if = "is_false")]
  pub requires_control: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct UsernameRules {
  #[serde(skip_serializing_if = "Option::is_none")]
  pub regex: Option<String>,
  pub case: UsernameCase,
  pub encode: UsernameEncoding,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub absent_template: Option<String>,
}

impl Default for UsernameRules {
  fn default() -> Self {
    Self {
      regex: None,
      case: UsernameCase::Preserve,
      encode: UsernameEncoding::SpaceOnly,
      absent_template: None,
    }
  }
}

#[derive(
  Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum UsernameCase {
  #[default]
  Preserve,
  Lower,
  Upper,
}

#[derive(
  Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum UsernameEncoding {
  #[default]
  SpaceOnly,
  PercentPath,
  None,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct RequestSpec {
  pub method: HttpMethod,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub url_template: Option<String>,
  #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
  pub headers: BTreeMap<String, String>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub body_template: Option<serde_json::Value>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub redirect_policy: Option<RedirectPolicy>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub timeout_ms: Option<u64>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub max_body_bytes: Option<usize>,
  #[serde(default = "default_true")]
  pub idempotent: bool,
}

impl Default for RequestSpec {
  fn default() -> Self {
    Self {
      method: HttpMethod::Get,
      url_template: None,
      headers: BTreeMap::new(),
      body_template: None,
      redirect_policy: None,
      timeout_ms: None,
      max_body_bytes: None,
      idempotent: true,
    }
  }
}

#[derive(
  Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "UPPERCASE")]
pub enum HttpMethod {
  Get,
  Head,
  Post,
  Put,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
pub struct DetectionSpec {
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub min_hit_score: Option<f32>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub min_miss_score: Option<f32>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub decision_margin: Option<f32>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub status_gate: Option<StatusGate>,
  pub signals: Vec<SignalSpec>,
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub block_signals: Vec<BlockSignal>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub control: Option<ControlSpec>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
pub struct StatusGate {
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub body_signals_allowed_status: Vec<u16>,
}

#[derive(
  Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceOutcome {
  Hit,
  Miss,
  Uncertain,
}

#[derive(
  Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum SignalKind {
  Status,
  Header,
  Redirect,
  BodySubstring,
  BodyRegex,
  HtmlTitle,
  CssSelector,
  JsonPath,
  CanonicalUrl,
  UsernameEcho,
  BodySimilarity,
  BodySize,
}

#[derive(
  Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum MatchOp {
  Exists,
  Equals,
  NotEquals,
  Contains,
  Regex,
  EqualsUsername,
  ContainsUsername,
}

#[derive(
  Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum EchoLocation {
  Title,
  Body,
  FinalUrl,
  ProfileUrl,
}

#[derive(
  Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum SimilarityDirection {
  SimilarToControl,
  DifferentFromControl,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
pub struct StatusMatch {
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub codes: Vec<u16>,
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub ranges: Vec<[u16; 2]>,
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub exclude_codes: Vec<u16>,
  #[serde(default, skip_serializing_if = "is_false")]
  pub negate: bool,
}

impl StatusMatch {
  #[must_use]
  pub fn matches(&self, status: u16) -> bool {
    if self.exclude_codes.contains(&status) {
      return self.negate;
    }
    let base = self.codes.contains(&status)
      || self
        .ranges
        .iter()
        .any(|[lo, hi]| status >= *lo && status <= *hi);
    base ^ self.negate
  }
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct SignalSpec {
  pub id: String,
  pub outcome: EvidenceOutcome,
  pub weight: f32,
  #[serde(flatten)]
  pub kind: SignalKindSpec,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SignalKindSpec {
  Status {
    #[serde(rename = "match")]
    match_spec: StatusMatch,
  },
  Header {
    header: String,
    op: MatchOp,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    value: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pattern: Option<String>,
  },
  Redirect {
    op: MatchOp,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    value: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pattern: Option<String>,
  },
  BodySubstring {
    value: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    case_insensitive: Option<bool>,
  },
  BodyRegex {
    pattern: String,
  },
  HtmlTitle {
    op: MatchOp,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    value: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pattern: Option<String>,
  },
  CssSelector {
    selector: String,
    op: MatchOp,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    attr: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    value: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pattern: Option<String>,
  },
  JsonPath {
    path: String,
    op: MatchOp,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    value: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pattern: Option<String>,
  },
  CanonicalUrl {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    selector: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pattern: Option<String>,
  },
  UsernameEcho {
    location: EchoLocation,
  },
  BodySimilarity {
    similarity_threshold: f32,
    direction: SimilarityDirection,
  },
  BodySize {
    range: [usize; 2],
  },
}

impl SignalKindSpec {
  #[must_use]
  pub const fn kind(&self) -> SignalKind {
    match self {
      Self::Status { .. } => SignalKind::Status,
      Self::Header { .. } => SignalKind::Header,
      Self::Redirect { .. } => SignalKind::Redirect,
      Self::BodySubstring { .. } => SignalKind::BodySubstring,
      Self::BodyRegex { .. } => SignalKind::BodyRegex,
      Self::HtmlTitle { .. } => SignalKind::HtmlTitle,
      Self::CssSelector { .. } => SignalKind::CssSelector,
      Self::JsonPath { .. } => SignalKind::JsonPath,
      Self::CanonicalUrl { .. } => SignalKind::CanonicalUrl,
      Self::UsernameEcho { .. } => SignalKind::UsernameEcho,
      Self::BodySimilarity { .. } => SignalKind::BodySimilarity,
      Self::BodySize { .. } => SignalKind::BodySize,
    }
  }
}

#[derive(
  Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum BlockClass {
  Blocked,
  RateLimited,
  Captcha,
  LoginRequired,
  Unsupported,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct BlockSignal {
  pub id: String,
  pub kind: SignalKind,
  #[serde(rename = "match", default, skip_serializing_if = "Option::is_none")]
  pub match_spec: Option<StatusMatch>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub pattern: Option<String>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub value: Option<String>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub header: Option<String>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub case_insensitive: Option<bool>,
  pub classify_as: BlockClass,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct ControlSpec {
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub absent_username: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
pub struct KnownControls {
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub claimed: Vec<String>,
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub absent: Vec<String>,
}

impl Site {
  #[must_use]
  pub fn probe_template(&self) -> &str {
    self
      .request
      .url_template
      .as_deref()
      .unwrap_or(&self.profile_url_template)
  }
}
