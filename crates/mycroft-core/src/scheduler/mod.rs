pub mod circuit_breaker;
pub mod host_limiter;
pub mod task_runner;

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Instant;

use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use mycroft_manifest::Manifest;

use crate::config::{RuntimeConfig, SchedulerLimits};
use crate::detect::Detector;
use crate::event::{EventSender, ScanEvent};
use crate::net::HttpExecutor;
use crate::planner::{HostKey, ScanPlan};
use crate::result::{
  RESULT_SCHEMA_VERSION, ScanReport, ScanSummary, SiteResult,
};

use host_limiter::HostState;
use task_runner::{TaskDeps, run_task};

pub struct CheckScheduler {
  executor: Arc<dyn HttpExecutor>,
  detector: Arc<Detector>,
  cfg: Arc<RuntimeConfig>,
}

impl CheckScheduler {
  #[must_use]
  pub fn new(
    executor: Arc<dyn HttpExecutor>,
    detector: Detector,
    cfg: RuntimeConfig,
  ) -> Self {
    Self {
      executor,
      detector: Arc::new(detector),
      cfg: Arc::new(cfg),
    }
  }

  pub async fn run(
    &self,
    plan: ScanPlan,
    manifest: Arc<Manifest>,
    events: EventSender,
    cancel: CancellationToken,
  ) -> ScanReport {
    let started_at = now_rfc3339();
    let start_instant = Instant::now();
    let scan_id = plan.scan_id.clone();

    events.send(ScanEvent::ScanStarted {
      scan_id: scan_id.clone(),
      task_count: plan.tasks.len(),
    });

    let mut summary = ScanSummary {
      sites_selected: plan.sites_selected,
      tasks_total: plan.tasks.len(),
      ..ScanSummary::default()
    };
    let mut results: Vec<SiteResult> =
      Vec::with_capacity(plan.tasks.len() + plan.skipped.len());

    for skipped in plan.skipped {
      summary.record(&skipped);
      events.send(ScanEvent::Result {
        result: Box::new(skipped.clone()),
      });
      results.push(skipped);
    }

    let hosts: Arc<Mutex<HashMap<HostKey, Arc<HostState>>>> =
      Arc::new(Mutex::new(HashMap::new()));
    let global =
      Arc::new(Semaphore::new(self.cfg.limits.global_concurrency.max(1)));
    let retry_count = Arc::new(AtomicU64::new(0));
    let deps = TaskDeps {
      manifest,
      executor: self.executor.clone(),
      detector: self.detector.clone(),
      cfg: self.cfg.clone(),
      events: events.clone(),
      retry_count: retry_count.clone(),
    };

    let mut join_set: JoinSet<SiteResult> = JoinSet::new();
    let mut tasks = plan.tasks.into_iter();
    let mut interrupted = false;

    loop {
      tokio::select! {
        biased;
        () = cancel.cancelled() => {
          interrupted = true;
          break;
        }
        permit = global.clone().acquire_owned() => {
          let Ok(permit) = permit else { break };
          let Some(task) = tasks.next() else {
            drop(permit);
            break;
          };
          let host = get_host(&hosts, &task.host_key, &self.cfg.limits);
          let deps = deps.clone();
          join_set.spawn(async move {
            let _permit = permit;
            run_task(task, host, deps).await
          });
        }
      }
    }

    if interrupted {
      join_set.abort_all();
    }

    while let Some(joined) = join_set.join_next().await {
      if let Ok(result) = joined {
        if result.control.is_some() {
          summary.control_probes += 1;
        }
        summary.record(&result);
        events.send(ScanEvent::Result {
          result: Box::new(result.clone()),
        });
        results.push(result);
      }
    }

    summary.usernames = results
      .iter()
      .map(|r| r.username.as_str())
      .collect::<HashSet<_>>()
      .len();
    summary.retries = usize::try_from(retry_count.load(Ordering::Relaxed))
      .unwrap_or(usize::MAX);
    summary.interrupted = interrupted;
    summary.elapsed_ms = start_instant
      .elapsed()
      .as_millis()
      .try_into()
      .unwrap_or(u64::MAX);

    events.send(ScanEvent::ScanFinished {
      summary: Box::new(summary.clone()),
    });

    ScanReport {
      schema_version: RESULT_SCHEMA_VERSION.to_string(),
      scan_id,
      started_at,
      finished_at: now_rfc3339(),
      summary,
      results,
    }
  }
}

fn get_host(
  hosts: &Mutex<HashMap<HostKey, Arc<HostState>>>,
  key: &HostKey,
  limits: &SchedulerLimits,
) -> Arc<HostState> {
  let mut map = lock_hosts(hosts);
  map
    .entry(key.clone())
    .or_insert_with(|| Arc::new(HostState::new(limits)))
    .clone()
}

fn lock_hosts(
  hosts: &Mutex<HashMap<HostKey, Arc<HostState>>>,
) -> MutexGuard<'_, HashMap<HostKey, Arc<HostState>>> {
  match hosts.lock() {
    Ok(guard) => guard,
    Err(poisoned) => poisoned.into_inner(),
  }
}

fn now_rfc3339() -> String {
  OffsetDateTime::now_utc()
    .format(&Rfc3339)
    .unwrap_or_default()
}
