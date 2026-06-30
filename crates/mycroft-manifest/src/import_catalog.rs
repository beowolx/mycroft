use std::collections::{BTreeMap, HashSet};

use serde_json::Value;

use crate::schema::{
  BlockClass, BlockSignal, ControlMode, EvidenceOutcome, HttpMethod, Manifest,
  ManifestDefaults, RedirectMode, RedirectPolicy, RequestSpec, SignalKind,
  SignalKindSpec, SignalSpec, Site, StatusMatch, UsernameCase,
  UsernameEncoding, UsernameRules,
};

pub const IMPORT_USER_AGENT: &str =
  "Mozilla/5.0 (X11; Linux x86_64; rv:129.0) Gecko/20100101 Firefox/129.0";

const WAF_FINGERPRINTS: &[(&str, &str)] = &[
  (
    "waf_cloudflare_dark",
    ".loading-spinner{visibility:hidden}body.no-js .challenge-running{display:none}body.dark{background-color:#222;color:#d9d9d9}body.dark a{color:#fff}body.dark a:hover{color:#ee730a;text-decoration:underline}body.dark .lds-ring div{border-color:#999 transparent transparent}body.dark .font-red{color:#b20f03}body.dark",
  ),
  (
    "waf_cloudflare_challenge",
    "<span id=\"challenge-error-text\">",
  ),
  ("waf_aws", "AwsWafIntegration.forceRefreshToken"),
  (
    "waf_perimeterx",
    "{return l.onPageView}}),Object.defineProperty(r,\"perimeterxIdentifiers\",{enumerable:",
  ),
];

#[derive(Debug, thiserror::Error)]
pub enum ImportError {
  #[error("top-level catalog data must be a JSON object")]
  NotAnObject,
  #[error("site '{site}': {reason}")]
  Site { site: String, reason: String },
}

#[must_use]
pub fn catalog_defaults() -> ManifestDefaults {
  ManifestDefaults {
    timeout_ms: 15_000,
    connect_timeout_ms: 7_000,
    max_body_bytes: 262_144,
    redirect_policy: RedirectPolicy {
      mode: RedirectMode::Follow,
      max_hops: 10,
    },
    control_mode: ControlMode::Auto,
    min_hit_score: 0.72,
    min_miss_score: 0.72,
    decision_margin: 0.18,
    user_agent: Some(IMPORT_USER_AGENT.to_string()),
    block_signals: WAF_FINGERPRINTS
      .iter()
      .map(|(id, body)| BlockSignal {
        id: (*id).to_string(),
        kind: SignalKind::BodySubstring,
        match_spec: None,
        pattern: None,
        value: Some((*body).to_string()),
        header: None,
        case_insensitive: Some(false),
        classify_as: BlockClass::Blocked,
      })
      .collect(),
  }
}

/// Converts a Sherlock-style catalog export into a mycroft manifest.
///
/// # Errors
///
/// Returns an error when the catalog is not a JSON object or an individual site
/// entry cannot be converted into a valid manifest site.
pub fn import_catalog(
  data: &Value,
  manifest_id: &str,
  generated_at: Option<String>,
) -> Result<Manifest, ImportError> {
  let object = data.as_object().ok_or(ImportError::NotAnObject)?;

  let mut entries: Vec<(&String, &Value)> = object
    .iter()
    .filter(|(k, _)| k.as_str() != "$schema")
    .collect();
  entries.sort_by(|a, b| a.0.cmp(b.0));

  let mut used_ids: HashSet<String> = HashSet::new();
  let mut sites = Vec::with_capacity(entries.len());
  for (name, entry) in entries {
    let id = unique_id(&slugify(name), &mut used_ids);
    let site =
      import_entry(name, &id, entry).map_err(|reason| ImportError::Site {
        site: name.clone(),
        reason,
      })?;
    sites.push(site);
  }
  sites.sort_by(|a, b| a.id.cmp(&b.id));

  Ok(Manifest {
    manifest_version: crate::schema::CURRENT_MANIFEST_VERSION,
    schema: Some("schemas/mycroft-manifest.v1.schema.json".to_string()),
    manifest_id: manifest_id.to_string(),
    generated_at,
    defaults: catalog_defaults(),
    sites,
  })
}

fn import_entry(name: &str, id: &str, entry: &Value) -> Result<Site, String> {
  let obj = entry.as_object().ok_or("entry is not an object")?;

  let url = obj
    .get("url")
    .and_then(Value::as_str)
    .ok_or("missing `url`")?;
  let url_main = obj
    .get("urlMain")
    .and_then(Value::as_str)
    .ok_or("missing `urlMain`")?;

  let error_types = string_or_array(obj.get("errorType"));
  if error_types.is_empty() {
    return Err("missing `errorType`".to_string());
  }

  let request_method = obj.get("request_method").and_then(Value::as_str);
  let method = resolve_method(request_method, &error_types)?;

  let url_probe = obj.get("urlProbe").and_then(Value::as_str);
  let body_template = obj.get("request_payload").map(convert_placeholder_json);

  let mut headers = BTreeMap::new();
  if let Some(map) = obj.get("headers").and_then(Value::as_object) {
    for (k, v) in map {
      if let Some(s) = v.as_str() {
        headers.insert(k.clone(), s.to_string());
      }
    }
  }

  let is_response_url = error_types.iter().any(|t| t == "response_url");
  let redirect_policy = if is_response_url {
    Some(RedirectPolicy {
      mode: RedirectMode::Manual,
      max_hops: 0,
    })
  } else {
    None
  };

  let request = RequestSpec {
    method,
    url_template: url_probe.map(convert_placeholder),
    headers,
    body_template,
    redirect_policy,
    timeout_ms: None,
    max_body_bytes: None,
    idempotent: true,
  };

  let error_codes = int_or_array(obj.get("errorCode"));
  let error_msgs = string_or_array(obj.get("errorMsg"));
  let signals = build_signals(&error_types, &error_codes, &error_msgs)?;

  let regex = obj
    .get("regexCheck")
    .and_then(Value::as_str)
    .map(ToString::to_string);
  let nsfw = obj.get("isNSFW").and_then(Value::as_bool).unwrap_or(false);
  let username_claimed = obj
    .get("username_claimed")
    .and_then(Value::as_str)
    .map(ToString::to_string);

  let known_controls =
    username_claimed.map(|claimed| crate::schema::KnownControls {
      claimed: vec![claimed],
      absent: Vec::new(),
    });

  Ok(Site {
    id: id.to_string(),
    name: name.to_string(),
    url_main: url_main.to_string(),
    enabled: true,
    tags: Vec::new(),
    nsfw,
    risk: None,
    username: UsernameRules {
      regex,
      case: UsernameCase::Preserve,
      encode: UsernameEncoding::SpaceOnly,
      absent_template: None,
    },
    profile_url_template: convert_placeholder(url),
    request,
    detection: crate::schema::DetectionSpec {
      min_hit_score: None,
      min_miss_score: None,
      decision_margin: None,
      status_gate: None,
      signals,
      block_signals: Vec::new(),
      control: None,
    },
    known_controls,
  })
}

fn resolve_method(
  explicit: Option<&str>,
  error_types: &[String],
) -> Result<HttpMethod, String> {
  if let Some(m) = explicit {
    return match m.to_ascii_uppercase().as_str() {
      "GET" => Ok(HttpMethod::Get),
      "HEAD" => Ok(HttpMethod::Head),
      "POST" => Ok(HttpMethod::Post),
      "PUT" => Ok(HttpMethod::Put),
      other => Err(format!("unsupported request_method '{other}'")),
    };
  }
  if error_types.iter().all(|t| t == "status_code") {
    Ok(HttpMethod::Head)
  } else {
    Ok(HttpMethod::Get)
  }
}

fn build_signals(
  error_types: &[String],
  error_codes: &[u16],
  error_msgs: &[String],
) -> Result<Vec<SignalSpec>, String> {
  let mut signals = Vec::new();

  for error_type in error_types {
    match error_type.as_str() {
      "status_code" => signals.extend(signal_pair(
        "status_claimed",
        "status_absent",
        error_codes,
      )),
      "response_url" => signals.extend(signal_pair(
        "response_url_claimed",
        "response_url_absent",
        &[],
      )),
      "message" => {
        signals.push(SignalSpec {
          id: "message_response".to_string(),
          outcome: EvidenceOutcome::Hit,
          weight: 0.8,
          kind: SignalKindSpec::Status {
            match_spec: StatusMatch {
              codes: Vec::new(),
              ranges: vec![[100, 599]],
              exclude_codes: Vec::new(),
              negate: false,
            },
          },
        });
        if error_msgs.is_empty() {
          return Err("message errorType requires `errorMsg`".to_string());
        }
        for (idx, msg) in error_msgs.iter().enumerate() {
          signals.push(SignalSpec {
            id: format!("message_miss_{idx}"),
            outcome: EvidenceOutcome::Miss,
            weight: 1.0,
            kind: SignalKindSpec::BodySubstring {
              value: msg.clone(),
              case_insensitive: Some(false),
            },
          });
        }
      }
      other => return Err(format!("unsupported errorType '{other}'")),
    }
  }
  Ok(signals)
}

fn signal_pair(
  claimed_id: &str,
  absent_id: &str,
  exclude_codes: &[u16],
) -> [SignalSpec; 2] {
  [
    status_signal(claimed_id, EvidenceOutcome::Hit, 0.9, exclude_codes, false),
    status_signal(absent_id, EvidenceOutcome::Miss, 0.9, exclude_codes, true),
  ]
}

fn status_signal(
  id: &str,
  outcome: EvidenceOutcome,
  weight: f32,
  exclude_codes: &[u16],
  negate: bool,
) -> SignalSpec {
  SignalSpec {
    id: id.to_string(),
    outcome,
    weight,
    kind: SignalKindSpec::Status {
      match_spec: StatusMatch {
        codes: Vec::new(),
        ranges: vec![[200, 299]],
        exclude_codes: exclude_codes.to_vec(),
        negate,
      },
    },
  }
}

fn convert_placeholder(s: &str) -> String {
  s.replace("{}", crate::template::USERNAME_PLACEHOLDER)
}

fn convert_placeholder_json(value: &Value) -> Value {
  crate::template::map_json_strings(value, &convert_placeholder)
}

fn string_or_array(value: Option<&Value>) -> Vec<String> {
  match value {
    Some(Value::String(s)) => vec![s.clone()],
    Some(Value::Array(items)) => items
      .iter()
      .filter_map(Value::as_str)
      .map(ToString::to_string)
      .collect(),
    _ => Vec::new(),
  }
}

fn int_or_array(value: Option<&Value>) -> Vec<u16> {
  match value {
    Some(Value::Number(n)) => n
      .as_u64()
      .and_then(|v| u16::try_from(v).ok())
      .into_iter()
      .collect(),
    Some(Value::Array(items)) => items
      .iter()
      .filter_map(Value::as_u64)
      .filter_map(|v| u16::try_from(v).ok())
      .collect(),
    _ => Vec::new(),
  }
}

fn slugify(name: &str) -> String {
  let mut out = String::with_capacity(name.len());
  let mut prev_underscore = false;
  for ch in name.chars() {
    if ch.is_ascii_alphanumeric() {
      out.push(ch.to_ascii_lowercase());
      prev_underscore = false;
    } else if !prev_underscore && !out.is_empty() {
      out.push('_');
      prev_underscore = true;
    }
  }
  let trimmed = out.trim_matches('_').to_string();
  if trimmed.is_empty() {
    "site".to_string()
  } else {
    trimmed
  }
}

fn unique_id(base: &str, used: &mut HashSet<String>) -> String {
  if used.insert(base.to_string()) {
    return base.to_string();
  }
  let mut n = 2;
  loop {
    let candidate = format!("{base}_{n}");
    if used.insert(candidate.clone()) {
      return candidate;
    }
    n += 1;
  }
}
