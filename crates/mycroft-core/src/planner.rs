use std::time::Duration;

use serde::Serialize;
use url::Url;

use mycroft_manifest::schema::ControlMode;
use mycroft_manifest::template;
use mycroft_manifest::{Manifest, ManifestDefaults, Site};

use crate::config::RuntimeConfig;
use crate::net::PreparedRequest;
use crate::result::{
  NetworkRoute, ProbeSummary, ResultErrorInfo, ResultErrorKind, ScanId,
  SiteResult, Verdict,
};
use crate::scan::ScanInput;
use crate::username::{
  Username, UsernameRuleError, apply_site_rules, generate_absent_username,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct CheckTaskId(pub u64);

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct HostKey(pub String);

#[derive(Clone, Debug)]
pub struct ControlPrep {
  pub request: PreparedRequest,
  pub username_for_url: String,
  pub username_raw: String,
}

#[derive(Clone, Debug)]
pub struct PreparedCheck {
  pub request: PreparedRequest,
  pub profile_url: String,
  pub username_for_url: String,
  pub username_raw: String,
  pub control: Option<ControlPrep>,
}

#[derive(Clone, Debug)]
pub struct CheckTask {
  pub id: CheckTaskId,
  pub username: Username,
  pub site_id: String,
  pub site_index: usize,
  pub host_key: HostKey,
  pub prepared: PreparedCheck,
}

#[derive(Debug)]
pub struct ScanPlan {
  pub scan_id: ScanId,
  pub tasks: Vec<CheckTask>,
  pub skipped: Vec<SiteResult>,
  pub sites_selected: usize,
}

#[derive(Debug, thiserror::Error)]
pub enum PlanError {
  #[error("no usernames provided")]
  NoUsernames,
  #[error("no sites matched the selection")]
  NoSites,
}

/// Builds the concrete check tasks for the selected usernames and sites.
///
/// # Errors
///
/// Returns an error when no usernames were supplied or the site selection
/// excludes every site.
pub fn build_scan_plan(
  input: &ScanInput,
  manifest: &Manifest,
  cfg: &RuntimeConfig,
) -> Result<ScanPlan, PlanError> {
  if input.usernames.is_empty() {
    return Err(PlanError::NoUsernames);
  }

  let selected: Vec<(usize, &Site)> = manifest
    .sites
    .iter()
    .enumerate()
    .filter(|(_, site)| input.selects(site))
    .collect();
  if selected.is_empty() {
    return Err(PlanError::NoSites);
  }

  let mut tasks = Vec::new();
  let mut skipped = Vec::new();
  let mut next_id = 0u64;

  for username in &input.usernames {
    for (site_index, site) in &selected {
      match plan_task(
        username,
        site,
        *site_index,
        &manifest.defaults,
        cfg,
        next_id,
      ) {
        Ok(task) => {
          tasks.push(task);
          next_id += 1;
        }
        Err(skip) => skipped.push(*skip),
      }
    }
  }

  Ok(ScanPlan {
    scan_id: ScanId::random(),
    tasks,
    skipped,
    sites_selected: selected.len(),
  })
}

fn plan_task(
  username: &Username,
  site: &Site,
  site_index: usize,
  defaults: &ManifestDefaults,
  cfg: &RuntimeConfig,
  id: u64,
) -> Result<CheckTask, Box<SiteResult>> {
  let encoded = match apply_site_rules(username, &site.username) {
    Ok(encoded) => encoded,
    Err(UsernameRuleError::RegexMismatch) => {
      return Err(Box::new(error_result(
        username,
        site,
        cfg.network_route(),
        Verdict::InvalidUsername,
        ResultErrorKind::InvalidUsernameForSite,
        "username does not satisfy the site's rules".to_string(),
      )));
    }
    Err(UsernameRuleError::InvalidRegex(reason)) => {
      return Err(Box::new(error_result(
        username,
        site,
        cfg.network_route(),
        Verdict::Uncertain,
        ResultErrorKind::DetectionRuleError,
        format!("site username regex is invalid: {reason}"),
      )));
    }
  };

  let prepared =
    build_prepared(site, defaults, cfg, &encoded).map_err(|reason| {
      Box::new(error_result(
        username,
        site,
        cfg.network_route(),
        Verdict::Uncertain,
        ResultErrorKind::HttpProtocol,
        reason,
      ))
    })?;

  Ok(CheckTask {
    id: CheckTaskId(id),
    username: username.clone(),
    site_id: site.id.clone(),
    site_index,
    host_key: host_key_of(&prepared.request.url),
    prepared,
  })
}

fn build_prepared(
  site: &Site,
  defaults: &ManifestDefaults,
  cfg: &RuntimeConfig,
  encoded: &crate::username::EncodedUsername,
) -> Result<PreparedCheck, String> {
  let (request, profile_url) =
    build_request(site, defaults, cfg, &encoded.for_url, &encoded.for_body)?;

  let control = build_control(site, defaults, cfg, &encoded.for_body);

  Ok(PreparedCheck {
    request,
    profile_url,
    username_for_url: encoded.for_url.clone(),
    username_raw: encoded.for_body.clone(),
    control,
  })
}

fn build_request(
  site: &Site,
  defaults: &ManifestDefaults,
  cfg: &RuntimeConfig,
  for_url: &str,
  for_body: &str,
) -> Result<(PreparedRequest, String), String> {
  let profile_url = template::interpolate(&site.profile_url_template, for_url);
  let probe = template::interpolate(site.probe_template(), for_url);
  let url = Url::parse(&probe).map_err(|e| format!("invalid URL: {e}"))?;

  let mut headers: Vec<(String, String)> = site
    .request
    .headers
    .iter()
    .map(|(k, v)| (k.clone(), template::interpolate(v, for_body)))
    .collect();

  let body = match &site.request.body_template {
    Some(tmpl) => {
      let interpolated = template::interpolate_json(tmpl, for_body);
      let bytes = serde_json::to_vec(&interpolated)
        .map_err(|e| format!("invalid body template: {e}"))?;
      if !headers
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("content-type"))
      {
        headers
          .push(("Content-Type".to_string(), "application/json".to_string()));
      }
      Some(bytes)
    }
    None => None,
  };

  let redirect_policy = site
    .request
    .redirect_policy
    .unwrap_or(defaults.redirect_policy);
  let timeout = site
    .request
    .timeout_ms
    .map_or(cfg.timeouts.request_timeout, Duration::from_millis);
  let max_body_bytes = site
    .request
    .max_body_bytes
    .unwrap_or(defaults.max_body_bytes)
    .min(cfg.max_body_bytes_hard_cap);

  Ok((
    PreparedRequest {
      method: site.request.method,
      url,
      headers,
      body,
      redirect_policy,
      timeout,
      max_body_bytes,
      idempotent: site.request.idempotent,
    },
    profile_url,
  ))
}

fn build_control(
  site: &Site,
  defaults: &ManifestDefaults,
  cfg: &RuntimeConfig,
  target: &str,
) -> Option<ControlPrep> {
  if cfg.control_mode == ControlMode::Off {
    return None;
  }
  let absent = absent_username(site, target)?;
  let encoded = apply_site_rules(&absent, &site.username).ok()?;
  let (request, _) =
    build_request(site, defaults, cfg, &encoded.for_url, &encoded.for_body)
      .ok()?;
  Some(ControlPrep {
    request,
    username_for_url: encoded.for_url,
    username_raw: encoded.for_body,
  })
}

fn absent_username(site: &Site, target: &str) -> Option<Username> {
  if let Some(named) = site
    .detection
    .control
    .as_ref()
    .and_then(|c| c.absent_username.as_deref())
    .or_else(|| {
      site
        .known_controls
        .as_ref()
        .and_then(|c| c.absent.first().map(String::as_str))
    })
  {
    return Username::parse(named).ok();
  }
  let mut rng = rand::rng();
  generate_absent_username(&site.username, target, &mut rng)
}

fn host_key_of(url: &Url) -> HostKey {
  HostKey(format!(
    "{}://{}",
    url.scheme(),
    url.host_str().unwrap_or("")
  ))
}

fn error_result(
  username: &Username,
  site: &Site,
  route: NetworkRoute,
  verdict: Verdict,
  kind: ResultErrorKind,
  message: String,
) -> SiteResult {
  SiteResult {
    username: username.as_str().to_string(),
    site_id: site.id.clone(),
    site_name: site.name.clone(),
    verdict,
    profile_url: None,
    probe: ProbeSummary::no_probe(route),
    control: None,
    evidence: Vec::new(),
    error: Some(ResultErrorInfo { kind, message }),
  }
}

#[cfg(test)]
mod tests {
  use mycroft_manifest::{Manifest, parse_manifest_str};

  use crate::config::{ProxyConfig, RuntimeConfig};
  use crate::planner::{PlanError, build_scan_plan};
  use crate::result::{NetworkRoute, ResultErrorKind, Verdict};
  use crate::scan::{ScanInput, SiteSelection};
  use crate::username::Username;

  fn open_site() -> Manifest {
    parse_manifest_str(
      r#"{
        "manifest_version":1, "manifest_id":"t",
        "sites":[{
          "id":"site","name":"Site","url_main":"https://site.test/",
          "profile_url_template":"https://site.test/{username}",
          "detection":{"signals":[
            {"id":"h","outcome":"hit","weight":0.9,"kind":"status","match":{"ranges":[[200,299]]}}
          ]}
        }]
      }"#,
    )
    .expect("valid manifest")
  }

  fn numeric_only_site() -> Manifest {
    parse_manifest_str(
      r#"{
        "manifest_version":1, "manifest_id":"t",
        "sites":[{
          "id":"num","name":"Num","url_main":"https://num.test/",
          "username":{"regex":"^[0-9]+$"},
          "profile_url_template":"https://num.test/{username}",
          "detection":{"signals":[
            {"id":"h","outcome":"hit","weight":0.9,"kind":"status","match":{"ranges":[[200,299]]}}
          ]}
        }]
      }"#,
    )
    .expect("valid manifest")
  }

  fn named_control_site() -> Manifest {
    parse_manifest_str(
      r#"{
        "manifest_version":1, "manifest_id":"t",
        "sites":[{
          "id":"site","name":"Site","url_main":"https://site.test/",
          "profile_url_template":"https://site.test/{username}",
          "detection":{
            "control":{"absent_username":"ghostuser"},
            "signals":[
              {"id":"h","outcome":"hit","weight":0.9,"kind":"status","match":{"ranges":[[200,299]]}}
            ]
          }
        }]
      }"#,
    )
    .expect("valid manifest")
  }

  fn input_for(username: &str) -> ScanInput {
    ScanInput {
      usernames: vec![Username::parse(username).expect("valid username")],
      site_selection: SiteSelection::default(),
      include_nsfw: false,
    }
  }

  #[test]
  fn valid_username_produces_one_task_keyed_by_host() {
    let plan = build_scan_plan(
      &input_for("alice"),
      &open_site(),
      &RuntimeConfig::default(),
    )
    .expect("plan builds");
    assert_eq!(plan.tasks.len(), 1);
    assert!(plan.skipped.is_empty());
    assert_eq!(plan.sites_selected, 1);
    assert_eq!(plan.tasks[0].host_key.0, "https://site.test");
  }

  #[test]
  fn username_failing_site_regex_is_skipped_as_invalid() {
    let plan = build_scan_plan(
      &input_for("alice"),
      &numeric_only_site(),
      &RuntimeConfig::default(),
    )
    .expect("plan builds");
    assert!(plan.tasks.is_empty());
    assert_eq!(plan.skipped.len(), 1);
    let skipped = &plan.skipped[0];
    assert_eq!(skipped.verdict, Verdict::InvalidUsername);
    assert_eq!(
      skipped.error.as_ref().expect("error").kind,
      ResultErrorKind::InvalidUsernameForSite
    );
  }

  #[test]
  fn skipped_result_reports_the_configured_route_not_direct() {
    let cfg = RuntimeConfig {
      proxy: Some(ProxyConfig {
        url: "socks5h://127.0.0.1:9050".to_string(),
        route: NetworkRoute::Tor,
      }),
      ..RuntimeConfig::default()
    };
    let plan = build_scan_plan(&input_for("alice"), &numeric_only_site(), &cfg)
      .expect("plan builds");
    assert_eq!(plan.skipped[0].probe.network_route, NetworkRoute::Tor);
  }

  #[test]
  fn named_absent_username_is_prepared_as_control() {
    let plan = build_scan_plan(
      &input_for("alice"),
      &named_control_site(),
      &RuntimeConfig::default(),
    )
    .expect("plan builds");
    let control = plan.tasks[0]
      .prepared
      .control
      .as_ref()
      .expect("control prepared");
    assert_eq!(control.username_raw, "ghostuser");
  }

  #[test]
  fn no_usernames_and_no_sites_are_errors() {
    let empty = ScanInput {
      usernames: Vec::new(),
      site_selection: SiteSelection::default(),
      include_nsfw: false,
    };
    assert!(matches!(
      build_scan_plan(&empty, &open_site(), &RuntimeConfig::default()),
      Err(PlanError::NoUsernames)
    ));

    let unmatched = ScanInput {
      site_selection: SiteSelection {
        include_sites: vec!["does-not-exist".to_string()],
        ..SiteSelection::default()
      },
      ..input_for("alice")
    };
    assert!(matches!(
      build_scan_plan(&unmatched, &open_site(), &RuntimeConfig::default()),
      Err(PlanError::NoSites)
    ));
  }
}
