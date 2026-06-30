use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;

use mycroft_core::NetworkError;
use mycroft_core::config::RuntimeConfig;
use mycroft_core::event::EventSender;
use mycroft_core::net::{HttpExecutor, PreparedRequest, ProbeResponse, Url};
use mycroft_core::scan::scan_with_executor;
use mycroft_core::{
  CancellationToken, ControlMode, Manifest, ScanInput, ScanReport,
  SiteSelection, Username, Verdict,
};
use mycroft_manifest::parse_manifest_str;

#[derive(Clone)]
enum Reply {
  Resp { status: u16, body: String },
  ConnectErr,
  HttpErr,
}

struct FakeExecutor {
  scripts: Mutex<HashMap<String, Vec<Reply>>>,
}

#[async_trait]
impl HttpExecutor for FakeExecutor {
  async fn execute(
    &self,
    request: PreparedRequest,
  ) -> Result<ProbeResponse, NetworkError> {
    let host = request.url.host_str().unwrap_or_default().to_string();
    let reply = next_reply(&self.scripts, &host);
    match reply {
      Reply::Resp { status, body } => {
        Ok(make_response(&request.url, status, &body))
      }
      Reply::ConnectErr => {
        Err(NetworkError::Connect("fake connect".to_string()))
      }
      Reply::HttpErr => Err(NetworkError::Http("fake http".to_string())),
    }
  }
}

fn next_reply(
  scripts: &Mutex<HashMap<String, Vec<Reply>>>,
  host: &str,
) -> Reply {
  let mut map = scripts.lock().expect("scripts lock");
  let queue = map.get_mut(host).expect("host is scripted");
  let reply = if queue.len() > 1 {
    queue.remove(0)
  } else {
    queue[0].clone()
  };
  drop(map);
  reply
}

fn fake(host: &str, replies: Vec<Reply>) -> FakeExecutor {
  let mut scripts = HashMap::new();
  scripts.insert(host.to_string(), replies);
  FakeExecutor {
    scripts: Mutex::new(scripts),
  }
}

fn make_response(url: &Url, status: u16, body: &str) -> ProbeResponse {
  ProbeResponse {
    request_url: url.clone(),
    final_url: url.clone(),
    status,
    headers: vec![("content-type".to_string(), "text/html".to_string())],
    redirect_chain: Vec::new(),
    body: body.as_bytes().to_vec(),
    body_truncated: false,
    elapsed: Duration::from_millis(1),
  }
}

fn status_manifest() -> Manifest {
  parse_manifest_str(
    r#"{
      "manifest_version": 1,
      "manifest_id": "test",
      "sites": [{
        "id": "site",
        "name": "Site",
        "url_main": "https://site.test/",
        "profile_url_template": "https://site.test/{username}",
        "detection": {
          "signals": [
            {"id":"hit","outcome":"hit","weight":0.9,"kind":"status","match":{"ranges":[[200,299]]}},
            {"id":"miss","outcome":"miss","weight":0.9,"kind":"status","match":{"ranges":[[200,299]],"negate":true}}
          ]
        }
      }]
    }"#,
  )
  .expect("valid manifest")
}

fn block_manifest() -> Manifest {
  parse_manifest_str(
    r#"{
      "manifest_version": 1,
      "manifest_id": "test",
      "sites": [{
        "id": "site",
        "name": "Site",
        "url_main": "https://site.test/",
        "profile_url_template": "https://site.test/{username}",
        "detection": {
          "signals": [
            {"id":"hit","outcome":"hit","weight":0.9,"kind":"status","match":{"ranges":[[200,299]]}}
          ],
          "block_signals": [
            {"id":"captcha","kind":"body_regex","pattern":"(?i)verify you are human","classify_as":"captcha"}
          ]
        }
      }]
    }"#,
  )
  .expect("valid manifest")
}

fn cfg_no_control() -> RuntimeConfig {
  RuntimeConfig {
    control_mode: ControlMode::Off,
    ..RuntimeConfig::default()
  }
}

async fn run(
  manifest: Manifest,
  cfg: RuntimeConfig,
  executor: FakeExecutor,
  cancel: CancellationToken,
) -> ScanReport {
  let input = ScanInput {
    usernames: vec![Username::parse("alice").expect("valid username")],
    site_selection: SiteSelection::default(),
    include_nsfw: false,
  };
  scan_with_executor(
    input,
    manifest,
    cfg,
    Arc::new(executor),
    EventSender::noop(),
    cancel,
  )
  .await
  .expect("scan completes")
}

#[tokio::test]
async fn status_2xx_is_found_through_scheduler() {
  let executor = fake(
    "site.test",
    vec![Reply::Resp {
      status: 200,
      body: String::new(),
    }],
  );
  let report = run(
    status_manifest(),
    cfg_no_control(),
    executor,
    CancellationToken::new(),
  )
  .await;
  assert_eq!(report.results.len(), 1);
  assert_eq!(report.results[0].verdict, Verdict::Found);
  assert_eq!(report.results[0].probe.status, Some(200));
  assert_eq!(report.summary.found, 1);
}

#[tokio::test]
async fn non_retryable_error_is_uncertain_with_no_probe() {
  let executor = fake("site.test", vec![Reply::HttpErr]);
  let report = run(
    status_manifest(),
    cfg_no_control(),
    executor,
    CancellationToken::new(),
  )
  .await;
  let result = &report.results[0];
  assert_eq!(result.verdict, Verdict::Uncertain);
  assert!(result.error.is_some());
  assert_eq!(result.probe.status, None);
  assert_eq!(report.summary.retries, 0);
}

#[tokio::test]
async fn retryable_error_then_success_counts_one_retry() {
  let executor = fake(
    "site.test",
    vec![
      Reply::ConnectErr,
      Reply::Resp {
        status: 200,
        body: String::new(),
      },
    ],
  );
  let report = run(
    status_manifest(),
    cfg_no_control(),
    executor,
    CancellationToken::new(),
  )
  .await;
  assert_eq!(report.results[0].verdict, Verdict::Found);
  assert_eq!(report.summary.retries, 1);
}

#[tokio::test]
async fn control_probe_runs_on_found_and_demotes_soft_404() {
  let executor = fake(
    "site.test",
    vec![Reply::Resp {
      status: 200,
      body: "generic".to_string(),
    }],
  );
  let report = run(
    status_manifest(),
    RuntimeConfig::default(),
    executor,
    CancellationToken::new(),
  )
  .await;
  assert_eq!(report.summary.control_probes, 1);
  assert_eq!(report.results[0].verdict, Verdict::NotFound);
}

#[tokio::test]
async fn control_probe_skipped_when_primary_not_found() {
  let executor = fake(
    "site.test",
    vec![Reply::Resp {
      status: 404,
      body: String::new(),
    }],
  );
  let report = run(
    status_manifest(),
    RuntimeConfig::default(),
    executor,
    CancellationToken::new(),
  )
  .await;
  assert_eq!(report.summary.control_probes, 0);
  assert_eq!(report.results[0].verdict, Verdict::NotFound);
}

#[tokio::test]
async fn block_signal_yields_blocked_verdict() {
  let executor = fake(
    "site.test",
    vec![Reply::Resp {
      status: 200,
      body: "please verify you are human".to_string(),
    }],
  );
  let report = run(
    block_manifest(),
    cfg_no_control(),
    executor,
    CancellationToken::new(),
  )
  .await;
  assert_eq!(report.results[0].verdict, Verdict::Captcha);
}

#[tokio::test]
async fn precancelled_scan_reports_interrupted() {
  let executor = fake(
    "site.test",
    vec![Reply::Resp {
      status: 200,
      body: String::new(),
    }],
  );
  let cancel = CancellationToken::new();
  cancel.cancel();
  let report = run(status_manifest(), cfg_no_control(), executor, cancel).await;
  assert!(report.summary.interrupted);
}
