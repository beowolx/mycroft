use std::time::Duration;

use serde::Serialize;
use url::Url;

use mycroft_manifest::schema::ControlMode;
use mycroft_manifest::template;
use mycroft_manifest::{Manifest, ManifestDefaults, Site, SubjectKind};

use crate::config::RuntimeConfig;
use crate::net::PreparedRequest;
use crate::result::{
  NetworkRoute, ProbeSummary, ResultErrorInfo, ResultErrorKind, ScanId,
  SiteResult, Verdict,
};
use crate::scan::ScanInput;
use crate::subject::{Email, EncodedSubject, generate_absent_email};
use crate::twostep::{MainTemplate, TwoStep};
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
  pub two_step: Option<TwoStep>,
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
        input.subject_kind,
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
  kind: SubjectKind,
  site: &Site,
  site_index: usize,
  defaults: &ManifestDefaults,
  cfg: &RuntimeConfig,
  id: u64,
) -> Result<CheckTask, Box<SiteResult>> {
  let encoded = encode_subject(username, kind, site).map_err(
    |(verdict, kind, message)| {
      Box::new(error_result(
        username,
        site,
        cfg.network_route(),
        verdict,
        kind,
        message,
      ))
    },
  )?;

  let prepared =
    build_prepared(site, defaults, cfg, kind, &encoded).map_err(|reason| {
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

fn encode_subject(
  username: &Username,
  kind: SubjectKind,
  site: &Site,
) -> Result<EncodedSubject, (Verdict, ResultErrorKind, String)> {
  match kind {
    SubjectKind::Username => match apply_site_rules(username, &site.username) {
      Ok(encoded) => Ok(EncodedSubject::from_username(encoded)),
      Err(UsernameRuleError::RegexMismatch) => Err((
        Verdict::InvalidUsername,
        ResultErrorKind::InvalidUsernameForSite,
        "username does not satisfy the site's rules".to_string(),
      )),
      Err(UsernameRuleError::InvalidRegex(reason)) => Err((
        Verdict::Uncertain,
        ResultErrorKind::DetectionRuleError,
        format!("site username regex is invalid: {reason}"),
      )),
    },
    SubjectKind::Email => match Email::parse(username.as_str()) {
      Ok(email) => Ok(email.encoded_subject()),
      Err(reason) => Err((
        Verdict::InvalidUsername,
        ResultErrorKind::InvalidUsernameForSite,
        format!("invalid email address: {reason}"),
      )),
    },
  }
}

fn build_prepared(
  site: &Site,
  defaults: &ManifestDefaults,
  cfg: &RuntimeConfig,
  kind: SubjectKind,
  encoded: &EncodedSubject,
) -> Result<PreparedCheck, String> {
  let profile_url =
    template::interpolate_vars(&site.profile_url_template, &encoded.for_url);

  let (request, two_step, control) = if let Some(pre) = &site.prerequest {
    let request = build_prerequest(pre, defaults, cfg, encoded)?;
    let main = build_main_template(site, defaults, cfg, encoded)?;
    let two_step = TwoStep {
      extractions: pre.extract.clone(),
      forward_cookies: pre.forward_cookies,
      main,
    };
    (request, Some(two_step), None)
  } else {
    let request = build_request(site, defaults, cfg, encoded)?;
    let control =
      build_control(site, defaults, cfg, kind, &encoded.primary_raw);
    (request, None, control)
  };

  Ok(PreparedCheck {
    request,
    two_step,
    profile_url,
    username_for_url: encoded.primary_for_url.clone(),
    username_raw: encoded.primary_raw.clone(),
    control,
  })
}

fn request_limits(
  site: &Site,
  defaults: &ManifestDefaults,
  cfg: &RuntimeConfig,
) -> (mycroft_manifest::RedirectPolicy, Duration, usize) {
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
  (redirect_policy, timeout, max_body_bytes)
}

type ProbeParts = (String, Vec<(String, String)>, Option<Vec<u8>>);

fn probe_parts(
  site: &Site,
  encoded: &EncodedSubject,
) -> Result<ProbeParts, String> {
  let probe =
    template::interpolate_vars(site.probe_template(), &encoded.for_url);

  let mut headers: Vec<(String, String)> = site
    .request
    .headers
    .iter()
    .map(|(k, v)| (k.clone(), template::interpolate_vars(v, &encoded.for_body)))
    .collect();

  let has_content_type = |headers: &[(String, String)]| {
    headers
      .iter()
      .any(|(k, _)| k.eq_ignore_ascii_case("content-type"))
  };

  let body = if site.request.body_form.is_empty() {
    match &site.request.body_template {
      Some(tmpl) => {
        let interpolated =
          template::interpolate_json_vars(tmpl, &encoded.for_body);
        let bytes = serde_json::to_vec(&interpolated)
          .map_err(|e| format!("invalid body template: {e}"))?;
        if !has_content_type(&headers) {
          headers
            .push(("Content-Type".to_string(), "application/json".to_string()));
        }
        Some(bytes)
      }
      None => None,
    }
  } else {
    let form = site
      .request
      .body_form
      .iter()
      .map(|(k, v)| {
        format!("{k}={}", template::interpolate_vars(v, &encoded.for_url))
      })
      .collect::<Vec<_>>()
      .join("&");
    if !has_content_type(&headers) {
      headers.push((
        "Content-Type".to_string(),
        "application/x-www-form-urlencoded".to_string(),
      ));
    }
    Some(form.into_bytes())
  };

  Ok((probe, headers, body))
}

fn build_request(
  site: &Site,
  defaults: &ManifestDefaults,
  cfg: &RuntimeConfig,
  encoded: &EncodedSubject,
) -> Result<PreparedRequest, String> {
  let (probe, headers, body) = probe_parts(site, encoded)?;
  let url = Url::parse(&probe).map_err(|e| format!("invalid URL: {e}"))?;
  let (redirect_policy, timeout, max_body_bytes) =
    request_limits(site, defaults, cfg);

  Ok(PreparedRequest {
    method: site.request.method,
    url,
    headers,
    body,
    redirect_policy,
    timeout,
    max_body_bytes,
    idempotent: site.request.idempotent,
  })
}

fn build_main_template(
  site: &Site,
  defaults: &ManifestDefaults,
  cfg: &RuntimeConfig,
  encoded: &EncodedSubject,
) -> Result<MainTemplate, String> {
  let (url, headers, body) = probe_parts(site, encoded)?;
  let (redirect_policy, timeout, max_body_bytes) =
    request_limits(site, defaults, cfg);

  Ok(MainTemplate {
    method: site.request.method,
    url,
    headers,
    body,
    redirect_policy,
    timeout,
    max_body_bytes,
    idempotent: site.request.idempotent,
  })
}

fn build_prerequest(
  pre: &mycroft_manifest::Prerequest,
  defaults: &ManifestDefaults,
  cfg: &RuntimeConfig,
  encoded: &EncodedSubject,
) -> Result<PreparedRequest, String> {
  let url_str = template::interpolate_vars(&pre.url_template, &encoded.for_url);
  let url = Url::parse(&url_str).map_err(|e| format!("invalid URL: {e}"))?;
  let headers: Vec<(String, String)> = pre
    .headers
    .iter()
    .map(|(k, v)| (k.clone(), template::interpolate_vars(v, &encoded.for_body)))
    .collect();

  Ok(PreparedRequest {
    method: pre.method,
    url,
    headers,
    body: None,
    redirect_policy: defaults.redirect_policy,
    timeout: cfg.timeouts.request_timeout,
    max_body_bytes: defaults.max_body_bytes.min(cfg.max_body_bytes_hard_cap),
    idempotent: true,
  })
}

fn build_control(
  site: &Site,
  defaults: &ManifestDefaults,
  cfg: &RuntimeConfig,
  kind: SubjectKind,
  target: &str,
) -> Option<ControlPrep> {
  if cfg.control_mode == ControlMode::Off {
    return None;
  }
  let encoded = match kind {
    SubjectKind::Username => {
      let absent = absent_username(site, target)?;
      EncodedSubject::from_username(
        apply_site_rules(&absent, &site.username).ok()?,
      )
    }
    SubjectKind::Email => {
      let mut rng = rand::rng();
      generate_absent_email(&mut rng).encoded_subject()
    }
  };
  let request = build_request(site, defaults, cfg, &encoded).ok()?;
  Some(ControlPrep {
    request,
    username_for_url: encoded.primary_for_url,
    username_raw: encoded.primary_raw,
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
  use mycroft_manifest::{Manifest, SubjectKind, parse_manifest_str};

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
      subject_kind: SubjectKind::Username,
      site_selection: SiteSelection::default(),
      include_nsfw: false,
      include_email_sending: false,
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

  fn email_site() -> Manifest {
    parse_manifest_str(
      r#"{
        "manifest_version":1, "manifest_id":"t",
        "sites":[{
          "id":"mail","name":"Mail","url_main":"https://mail.test/",
          "supports":["email"],
          "username":{"encode":"none"},
          "profile_url_template":"https://mail.test/signup",
          "request":{"method":"GET","url_template":"https://mail.test/check?email={email}"},
          "detection":{"signals":[
            {"id":"h","outcome":"hit","weight":0.9,"kind":"json_path","path":"$.status","op":"equals","value":20}
          ]}
        }]
      }"#,
    )
    .expect("valid manifest")
  }

  fn email_input_for(email: &str) -> ScanInput {
    ScanInput {
      usernames: vec![Username::parse(email).expect("valid subject")],
      subject_kind: SubjectKind::Email,
      site_selection: SiteSelection::default(),
      include_nsfw: false,
      include_email_sending: false,
    }
  }

  #[test]
  fn email_subject_interpolates_encoded_address_into_url() {
    let plan = build_scan_plan(
      &email_input_for("perneldoreen@gmail.com"),
      &email_site(),
      &RuntimeConfig::default(),
    )
    .expect("plan builds");
    assert_eq!(plan.tasks.len(), 1);
    assert_eq!(
      plan.tasks[0].prepared.request.url.as_str(),
      "https://mail.test/check?email=perneldoreen%40gmail.com"
    );
    assert_eq!(
      plan.tasks[0].prepared.username_raw,
      "perneldoreen@gmail.com"
    );
  }

  #[test]
  fn username_scan_does_not_select_email_only_site() {
    assert!(matches!(
      build_scan_plan(
        &input_for("alice"),
        &email_site(),
        &RuntimeConfig::default()
      ),
      Err(PlanError::NoSites)
    ));
  }

  #[test]
  fn invalid_email_is_skipped_as_invalid() {
    let plan = build_scan_plan(
      &email_input_for("not-an-email"),
      &email_site(),
      &RuntimeConfig::default(),
    )
    .expect("plan builds");
    assert!(plan.tasks.is_empty());
    assert_eq!(plan.skipped.len(), 1);
    assert_eq!(plan.skipped[0].verdict, Verdict::InvalidUsername);
  }

  fn email_sending_form_site() -> Manifest {
    parse_manifest_str(
      r#"{
        "manifest_version":1, "manifest_id":"t",
        "sites":[{
          "id":"mail","name":"Mail","url_main":"https://mail.test/",
          "supports":["email"],"sends_email":true,
          "username":{"encode":"none"},
          "profile_url_template":"https://mail.test/",
          "request":{
            "method":"POST",
            "url_template":"https://mail.test/restore",
            "body_form":{"email":"{email}","htmlencoded":"false"}
          },
          "detection":{"signals":[
            {"id":"h","outcome":"hit","weight":0.9,"kind":"json_path","path":"$.status","op":"equals","value":200}
          ]}
        }]
      }"#,
    )
    .expect("valid manifest")
  }

  #[test]
  fn email_sending_site_excluded_unless_opted_in() {
    let mut input = email_input_for("a@b.com");
    assert!(matches!(
      build_scan_plan(
        &input,
        &email_sending_form_site(),
        &RuntimeConfig::default()
      ),
      Err(PlanError::NoSites)
    ));
    input.include_email_sending = true;
    let plan = build_scan_plan(
      &input,
      &email_sending_form_site(),
      &RuntimeConfig::default(),
    )
    .expect("plan builds");
    assert_eq!(plan.tasks.len(), 1);
  }

  fn two_step_site() -> Manifest {
    parse_manifest_str(
      r#"{
        "manifest_version":1, "manifest_id":"t",
        "sites":[{
          "id":"ts","name":"TS","url_main":"https://ts.test/",
          "supports":["email"],
          "username":{"encode":"none"},
          "profile_url_template":"https://ts.test/",
          "prerequest":{
            "method":"GET",
            "url_template":"https://ts.test/register",
            "forward_cookies":true,
            "extract":[{"name":"token","source":"regex","pattern":"tok=([a-z0-9]+)"}]
          },
          "request":{
            "method":"POST",
            "url_template":"https://ts.test/validate",
            "headers":{"Authorization":"Bearer {var:token}"},
            "body_template":{"email":"{email}"}
          },
          "detection":{"signals":[
            {"id":"h","outcome":"hit","weight":0.9,"kind":"json_path","path":"$.code","op":"equals","value":2}
          ]}
        }]
      }"#,
    )
    .expect("valid manifest")
  }

  #[test]
  #[allow(
    clippy::literal_string_with_formatting_args,
    reason = "asserting on a literal placeholder left for runtime substitution"
  )]
  fn two_step_site_prepares_prerequest_and_deferred_main() {
    let plan = build_scan_plan(
      &email_input_for("a@b.com"),
      &two_step_site(),
      &RuntimeConfig::default(),
    )
    .expect("plan builds");
    let prepared = &plan.tasks[0].prepared;
    assert_eq!(prepared.request.url.as_str(), "https://ts.test/register");
    let two_step = prepared.two_step.as_ref().expect("two_step present");
    assert_eq!(two_step.main.url, "https://ts.test/validate");
    assert!(
      two_step
        .main
        .headers
        .iter()
        .any(|(k, v)| k == "Authorization" && v == "Bearer {var:token}")
    );
    assert!(prepared.control.is_none());
    assert_eq!(two_step.extractions.len(), 1);
  }

  #[test]
  fn form_body_is_percent_encoded_and_joined() {
    let mut input = email_input_for("perneldoreen@gmail.com");
    input.include_email_sending = true;
    let plan = build_scan_plan(
      &input,
      &email_sending_form_site(),
      &RuntimeConfig::default(),
    )
    .expect("plan builds");
    let body = plan.tasks[0]
      .prepared
      .request
      .body
      .as_ref()
      .expect("form body present");
    assert_eq!(
      String::from_utf8(body.clone()).unwrap(),
      "email=perneldoreen%40gmail.com&htmlencoded=false"
    );
    let has_form_ct =
      plan.tasks[0].prepared.request.headers.iter().any(|(k, v)| {
        k.eq_ignore_ascii_case("content-type")
          && v == "application/x-www-form-urlencoded"
      });
    assert!(has_form_ct);
  }

  #[test]
  fn no_usernames_and_no_sites_are_errors() {
    let empty = ScanInput {
      usernames: Vec::new(),
      subject_kind: SubjectKind::Username,
      site_selection: SiteSelection::default(),
      include_nsfw: false,
      include_email_sending: false,
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
