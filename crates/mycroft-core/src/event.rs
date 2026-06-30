use serde::Serialize;
use tokio::sync::mpsc;

use crate::planner::CheckTaskId;
use crate::result::{ScanId, ScanSummary, SiteResult};

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ScanEvent {
  ScanStarted {
    scan_id: ScanId,
    task_count: usize,
  },
  TaskStarted {
    task_id: CheckTaskId,
    username: String,
    site_id: String,
  },
  TaskRetried {
    task_id: CheckTaskId,
    attempt: u8,
    reason: String,
  },
  Result {
    result: Box<SiteResult>,
  },
  HostCircuitOpen {
    host: String,
    until_ms: u64,
    reason: String,
  },
  ScanFinished {
    summary: Box<ScanSummary>,
  },
}

pub type EventReceiver = mpsc::UnboundedReceiver<ScanEvent>;

#[derive(Clone)]
pub struct EventSender(Option<mpsc::UnboundedSender<ScanEvent>>);

impl EventSender {
  #[must_use]
  pub fn channel() -> (Self, EventReceiver) {
    let (tx, rx) = mpsc::unbounded_channel();
    (Self(Some(tx)), rx)
  }

  #[must_use]
  pub const fn noop() -> Self {
    Self(None)
  }

  pub fn send(&self, event: ScanEvent) {
    if let Some(tx) = &self.0 {
      let _ = tx.send(event);
    }
  }
}
