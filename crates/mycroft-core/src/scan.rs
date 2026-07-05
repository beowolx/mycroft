use std::sync::Arc;

use tokio_util::sync::CancellationToken;

use mycroft_manifest::{Manifest, Site, SubjectKind};

use crate::config::RuntimeConfig;
use crate::detect::Detector;
use crate::error::ScanError;
use crate::event::EventSender;
use crate::net::{HttpExecutor, ReqwestHttpExecutor};
use crate::planner::{PlanError, build_scan_plan};
use crate::result::ScanReport;
use crate::scheduler::CheckScheduler;
use crate::username::Username;

#[derive(Clone, Debug, Default)]
pub struct SiteSelection {
  pub include_sites: Vec<String>,
  pub exclude_sites: Vec<String>,
  pub include_tags: Vec<String>,
  pub exclude_tags: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct ScanInput {
  pub usernames: Vec<Username>,
  pub subject_kind: SubjectKind,
  pub site_selection: SiteSelection,
  pub include_nsfw: bool,
  pub include_email_sending: bool,
}

impl ScanInput {
  #[must_use]
  pub fn selects(&self, site: &Site) -> bool {
    if !site.enabled {
      return false;
    }
    if !site.supports_kind(self.subject_kind) {
      return false;
    }
    if site.nsfw && !self.include_nsfw {
      return false;
    }
    if site.sends_email && !self.include_email_sending {
      return false;
    }
    let sel = &self.site_selection;
    if !sel.include_sites.is_empty()
      && !sel.include_sites.iter().any(|s| site_matches(site, s))
    {
      return false;
    }
    if sel.exclude_sites.iter().any(|s| site_matches(site, s)) {
      return false;
    }
    if !sel.include_tags.is_empty() && !has_any_tag(site, &sel.include_tags) {
      return false;
    }
    if has_any_tag(site, &sel.exclude_tags) {
      return false;
    }
    true
  }
}

#[must_use]
pub fn site_matches(site: &Site, needle: &str) -> bool {
  site.id.eq_ignore_ascii_case(needle) || site.name.eq_ignore_ascii_case(needle)
}

fn has_any_tag(site: &Site, tags: &[String]) -> bool {
  tags
    .iter()
    .any(|t| site.tags.iter().any(|st| st.eq_ignore_ascii_case(t)))
}

/// Runs a scan with the default HTTP executor and no event stream.
///
/// # Errors
///
/// Returns an error when input planning fails or the network executor cannot be
/// configured.
pub async fn scan(
  input: ScanInput,
  manifest: Manifest,
  cfg: RuntimeConfig,
) -> Result<ScanReport, ScanError> {
  scan_with_events(
    input,
    manifest,
    cfg,
    EventSender::noop(),
    CancellationToken::new(),
  )
  .await
}

/// Runs a scan with the default HTTP executor and an event stream.
///
/// # Errors
///
/// Returns an error when input planning fails or the network executor cannot be
/// configured.
pub async fn scan_with_events(
  input: ScanInput,
  manifest: Manifest,
  cfg: RuntimeConfig,
  events: EventSender,
  cancel: CancellationToken,
) -> Result<ScanReport, ScanError> {
  let executor = ReqwestHttpExecutor::new(&cfg)?;
  scan_with_executor(input, manifest, cfg, Arc::new(executor), events, cancel)
    .await
}

/// Runs a scan with a caller-provided HTTP executor.
///
/// # Errors
///
/// Returns an error when no usernames are provided or no sites are selected.
pub async fn scan_with_executor(
  input: ScanInput,
  manifest: Manifest,
  cfg: RuntimeConfig,
  executor: Arc<dyn HttpExecutor>,
  events: EventSender,
  cancel: CancellationToken,
) -> Result<ScanReport, ScanError> {
  if input.usernames.is_empty() {
    return Err(ScanError::NoUsernames);
  }
  let plan = build_scan_plan(&input, &manifest, &cfg).map_err(|e| match e {
    PlanError::NoUsernames => ScanError::NoUsernames,
    PlanError::NoSites => ScanError::NoSites,
  })?;
  let detector = Detector::new(&manifest.defaults);
  let scheduler = CheckScheduler::new(executor, detector, cfg);
  Ok(
    scheduler
      .run(plan, Arc::new(manifest), events, cancel)
      .await,
  )
}
