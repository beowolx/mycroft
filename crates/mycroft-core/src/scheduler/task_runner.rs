use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use mycroft_manifest::schema::ControlMode;
use mycroft_manifest::{Manifest, Site};

use crate::config::RuntimeConfig;
use crate::detect::{ControlInput, DetectionResult, Detector};
use crate::error::NetworkError;
use crate::event::{EventSender, ScanEvent};
use crate::net::{HttpExecutor, PreparedRequest, ProbeResponse};
use crate::planner::{CheckTask, PreparedCheck};
use crate::result::{
  ControlSummary, NetworkRoute, ProbeSummary, RedirectSummary, ResultErrorInfo,
  ResultErrorKind, SiteResult, Verdict,
};
use crate::scheduler::host_limiter::{HostState, ProbeOutcome};

#[derive(Clone)]
pub struct TaskDeps {
  pub manifest: Arc<Manifest>,
  pub executor: Arc<dyn HttpExecutor>,
  pub detector: Arc<Detector>,
  pub cfg: Arc<RuntimeConfig>,
  pub events: EventSender,
  pub retry_count: Arc<AtomicU64>,
}

pub async fn run_task(
  task: CheckTask,
  host: Arc<HostState>,
  deps: TaskDeps,
) -> SiteResult {
  deps.events.send(ScanEvent::TaskStarted {
    task_id: task.id,
    username: task.username.to_string(),
    site_id: task.site_id.clone(),
  });

  let site = &deps.manifest.sites[task.site_index];
  let site_name = site.name.clone();
  let route = deps.cfg.network_route();
  let Some(_permit) = host.acquire().await else {
    return blocked_result(
      &task,
      &site_name,
      Verdict::RateLimited,
      ResultErrorKind::RateLimited,
      "host limiter is closed",
      route,
    );
  };

  if !host.allow(Instant::now()) {
    return blocked_result(
      &task,
      &site_name,
      Verdict::RateLimited,
      ResultErrorKind::RateLimited,
      "host circuit breaker is open",
      route,
    );
  }

  host.rate_limit().await;
  let primary = match run_primary(&task, &deps, &host).await {
    Ok(response) => response,
    Err(error) => {
      if let Some(until_ms) =
        host.record_outcome(ProbeOutcome::Failure, Instant::now())
      {
        emit_circuit_open(
          &deps,
          &task,
          until_ms,
          format!("network error: {error}"),
        );
      }
      return network_error_result(&task, &site_name, route, &error);
    }
  };

  let prepared = &task.prepared;
  let first = deps.detector.evaluate(
    site,
    &prepared.username_for_url,
    &prepared.username_raw,
    &prepared.profile_url,
    &primary,
    None,
  );

  let (detection, control) =
    detect_with_control(site, prepared, &primary, first, &deps, &host, &task)
      .await;

  let outcome = breaker_outcome(primary.status, detection.verdict);
  if let Some(until_ms) = host.record_outcome(outcome, Instant::now()) {
    emit_circuit_open(
      &deps,
      &task,
      until_ms,
      format!(
        "status {} verdict {}",
        primary.status,
        detection.verdict.as_str()
      ),
    );
  }

  build_result(
    &task,
    &site_name,
    route,
    &primary,
    control.as_ref(),
    detection,
  )
}

async fn detect_with_control(
  site: &Site,
  prepared: &PreparedCheck,
  primary: &ProbeResponse,
  first: DetectionResult,
  deps: &TaskDeps,
  host: &HostState,
  task: &CheckTask,
) -> (DetectionResult, Option<ProbeResponse>) {
  let run_control = match deps.cfg.control_mode {
    ControlMode::Off => false,
    ControlMode::Auto => first.verdict == Verdict::Found,
    ControlMode::Strict => true,
  };
  let Some(control_prep) = prepared.control.as_ref().filter(|_| run_control)
  else {
    return (first, None);
  };

  host.rate_limit().await;
  run_probe(&control_prep.request, deps, task).await.map_or(
    (first, None),
    |response| {
      let detection = deps.detector.evaluate(
        site,
        &prepared.username_for_url,
        &prepared.username_raw,
        &prepared.profile_url,
        primary,
        Some(ControlInput {
          response: &response,
          username_for_url: &control_prep.username_for_url,
          username_raw: &control_prep.username_raw,
        }),
      );
      (detection, Some(response))
    },
  )
}

const fn breaker_outcome(status: u16, verdict: Verdict) -> ProbeOutcome {
  if matches!(status, 429 | 500 | 502 | 503 | 504)
    || matches!(
      verdict,
      Verdict::Blocked | Verdict::RateLimited | Verdict::Captcha
    )
  {
    ProbeOutcome::Failure
  } else {
    ProbeOutcome::Success
  }
}

fn emit_circuit_open(
  deps: &TaskDeps,
  task: &CheckTask,
  until_ms: u64,
  reason: String,
) {
  deps.events.send(ScanEvent::HostCircuitOpen {
    host: task.host_key.0.clone(),
    until_ms,
    reason,
  });
}

async fn run_primary(
  task: &CheckTask,
  deps: &TaskDeps,
  host: &HostState,
) -> Result<ProbeResponse, NetworkError> {
  let first = run_probe(&task.prepared.request, deps, task).await?;
  let Some(two_step) = &task.prepared.two_step else {
    return Ok(first);
  };
  let vars = crate::twostep::extract_vars(&first, &two_step.extractions)
    .map_err(NetworkError::Http)?;
  let cookies = if two_step.forward_cookies {
    crate::twostep::collect_cookies(&first)
  } else {
    None
  };
  let main =
    crate::twostep::finalize_main(&two_step.main, &vars, cookies.as_deref())
      .map_err(NetworkError::Http)?;
  host.rate_limit().await;
  run_probe(&main, deps, task).await
}

async fn run_probe(
  request: &PreparedRequest,
  deps: &TaskDeps,
  task: &CheckTask,
) -> Result<ProbeResponse, NetworkError> {
  let max_retries = deps.cfg.retries.max_retries;
  let mut attempt: u8 = 0;
  loop {
    match deps.executor.execute(request.clone()).await {
      Ok(response) => return Ok(response),
      Err(error) if attempt < max_retries && error.is_retryable() => {
        attempt += 1;
        deps.retry_count.fetch_add(1, Ordering::Relaxed);
        deps.events.send(ScanEvent::TaskRetried {
          task_id: task.id,
          attempt,
          reason: error.to_string(),
        });
        tokio::time::sleep(backoff(
          deps.cfg.retries.base_backoff,
          deps.cfg.retries.max_backoff,
          attempt,
          task.id.0,
        ))
        .await;
      }
      Err(error) => return Err(error),
    }
  }
}

fn backoff(base: Duration, max: Duration, attempt: u8, seed: u64) -> Duration {
  let base_ms = duration_millis_u64(base);
  let shift = u32::from(attempt.saturating_sub(1));
  let multiplier = 1u64.checked_shl(shift).unwrap_or(u64::MAX);
  let exp = base_ms.saturating_mul(multiplier);
  let capped = exp.min(duration_millis_u64(max));
  let jitter = seed % 100;
  Duration::from_millis(capped.saturating_add(jitter))
}

fn duration_millis_u64(duration: Duration) -> u64 {
  u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn build_result(
  task: &CheckTask,
  site_name: &str,
  route: NetworkRoute,
  primary: &ProbeResponse,
  control: Option<&ProbeResponse>,
  detection: DetectionResult,
) -> SiteResult {
  let probe = ProbeSummary {
    status: Some(primary.status),
    final_url: Some(primary.final_url.as_str().to_string()),
    elapsed_ms: duration_millis_u64(primary.elapsed),
    body_truncated: primary.body_truncated,
    redirects: primary
      .redirect_chain
      .iter()
      .map(|hop| RedirectSummary {
        status: hop.status,
        url: hop.to.as_str().to_string(),
      })
      .collect(),
    network_route: route,
  };

  let control_summary = control.map(|c| ControlSummary {
    status: Some(c.status),
    final_url: Some(c.final_url.as_str().to_string()),
    similarity: detection.control_similarity,
  });

  SiteResult {
    username: task.username.to_string(),
    site_id: task.site_id.clone(),
    site_name: site_name.to_string(),
    verdict: detection.verdict,
    profile_url: Some(task.prepared.profile_url.clone()),
    probe,
    control: control_summary,
    evidence: detection.evidence,
    error: verdict_error(detection.verdict),
  }
}

fn verdict_error(verdict: Verdict) -> Option<ResultErrorInfo> {
  let (kind, message) = match verdict {
    Verdict::Blocked => (
      ResultErrorKind::Blocked,
      "request was blocked (WAF/bot challenge)",
    ),
    Verdict::RateLimited => (ResultErrorKind::RateLimited, "rate limited"),
    Verdict::Captcha => (ResultErrorKind::Captcha, "CAPTCHA challenge"),
    Verdict::LoginRequired => (
      ResultErrorKind::LoginRequired,
      "login required to view profile",
    ),
    _ => return None,
  };
  Some(ResultErrorInfo {
    kind,
    message: message.to_string(),
  })
}

fn error_result(
  task: &CheckTask,
  site_name: &str,
  route: NetworkRoute,
  verdict: Verdict,
  error: ResultErrorInfo,
) -> SiteResult {
  SiteResult {
    username: task.username.to_string(),
    site_id: task.site_id.clone(),
    site_name: site_name.to_string(),
    verdict,
    profile_url: Some(task.prepared.profile_url.clone()),
    probe: ProbeSummary::no_probe(route),
    control: None,
    evidence: Vec::new(),
    error: Some(error),
  }
}

fn network_error_result(
  task: &CheckTask,
  site_name: &str,
  route: NetworkRoute,
  error: &NetworkError,
) -> SiteResult {
  error_result(
    task,
    site_name,
    route,
    Verdict::Uncertain,
    ResultErrorInfo {
      kind: error.kind(),
      message: error.to_string(),
    },
  )
}

fn blocked_result(
  task: &CheckTask,
  site_name: &str,
  verdict: Verdict,
  kind: ResultErrorKind,
  message: &str,
  route: NetworkRoute,
) -> SiteResult {
  error_result(
    task,
    site_name,
    route,
    verdict,
    ResultErrorInfo {
      kind,
      message: message.to_string(),
    },
  )
}

#[cfg(test)]
mod tests {
  use std::time::Duration;

  use crate::result::Verdict;
  use crate::scheduler::host_limiter::ProbeOutcome;
  use crate::scheduler::task_runner::{backoff, breaker_outcome};

  #[test]
  fn backoff_grows_exponentially_then_caps() {
    let base = Duration::from_millis(500);
    let max = Duration::from_secs(5);
    assert_eq!(backoff(base, max, 1, 0).as_millis(), 500);
    assert_eq!(backoff(base, max, 2, 0).as_millis(), 1000);
    assert_eq!(backoff(base, max, 3, 0).as_millis(), 2000);
    assert_eq!(backoff(base, max, 10, 0).as_millis(), 5000);
  }

  #[test]
  fn backoff_jitter_is_stable_and_bounded() {
    let base = Duration::from_millis(500);
    let max = Duration::from_secs(5);
    assert_eq!(backoff(base, max, 1, 42), backoff(base, max, 1, 42));
    assert_eq!(backoff(base, max, 1, 42).as_millis(), 542);
  }

  #[test]
  fn breaker_counts_blocks_and_5xx_as_failures() {
    assert_eq!(breaker_outcome(200, Verdict::Found), ProbeOutcome::Success);
    assert_eq!(
      breaker_outcome(404, Verdict::NotFound),
      ProbeOutcome::Success
    );
    assert_eq!(
      breaker_outcome(200, Verdict::Blocked),
      ProbeOutcome::Failure
    );
    assert_eq!(
      breaker_outcome(503, Verdict::NotFound),
      ProbeOutcome::Failure
    );
    assert_eq!(
      breaker_outcome(429, Verdict::RateLimited),
      ProbeOutcome::Failure
    );
  }
}
