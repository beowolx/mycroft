use std::time::Duration;

use mycroft_core::detect::{ControlInput, Detector};
use mycroft_core::net::{ProbeResponse, Url};
use mycroft_core::result::Verdict;
use mycroft_manifest::{Manifest, parse_manifest_str};

fn manifest(detection: &str) -> Manifest {
  let json = format!(
    r#"{{
      "manifest_version": 1,
      "manifest_id": "test",
      "sites": [{{
        "id": "site",
        "name": "Site",
        "url_main": "https://site.test/",
        "profile_url_template": "https://site.test/{{username}}",
        "detection": {detection}
      }}]
    }}"#
  );
  parse_manifest_str(&json).expect("valid test manifest")
}

fn response(status: u16, body: &str) -> ProbeResponse {
  let url = Url::parse("https://site.test/u").unwrap();
  ProbeResponse {
    request_url: url.clone(),
    final_url: url,
    status,
    headers: vec![("content-type".to_string(), "text/html".to_string())],
    redirect_chain: Vec::new(),
    body: body.as_bytes().to_vec(),
    body_truncated: false,
    elapsed: Duration::ZERO,
  }
}

fn verdict(m: &Manifest, primary: &ProbeResponse) -> Verdict {
  let detector = Detector::new(&m.defaults);
  detector
    .evaluate(
      &m.sites[0],
      "alice",
      "alice",
      "https://site.test/alice",
      primary,
      None,
    )
    .verdict
}

const STATUS_SITE: &str = r#"{
  "signals": [
    {"id":"hit","outcome":"hit","weight":0.9,"kind":"status","match":{"ranges":[[200,299]]}},
    {"id":"miss","outcome":"miss","weight":0.9,"kind":"status","match":{"ranges":[[200,299]],"negate":true}}
  ]
}"#;

#[test]
fn status_2xx_is_found() {
  let m = manifest(STATUS_SITE);
  assert_eq!(verdict(&m, &response(200, "")), Verdict::Found);
}

#[test]
fn status_404_is_not_found() {
  let m = manifest(STATUS_SITE);
  assert_eq!(verdict(&m, &response(404, "")), Verdict::NotFound);
}

#[test]
fn message_error_present_is_not_found() {
  let m = manifest(
    r#"{
      "signals": [
        {"id":"resp","outcome":"hit","weight":0.8,"kind":"status","match":{"ranges":[[100,599]]}},
        {"id":"err","outcome":"miss","weight":1.0,"kind":"body_substring","value":"not found"}
      ]
    }"#,
  );
  assert_eq!(
    verdict(&m, &response(200, "user not found here")),
    Verdict::NotFound
  );
}

#[test]
fn message_error_absent_is_found() {
  let m = manifest(
    r#"{
      "signals": [
        {"id":"resp","outcome":"hit","weight":0.8,"kind":"status","match":{"ranges":[[100,599]]}},
        {"id":"err","outcome":"miss","weight":1.0,"kind":"body_substring","value":"not found"}
      ]
    }"#,
  );
  assert_eq!(
    verdict(&m, &response(200, "welcome to alice's profile")),
    Verdict::Found
  );
}

#[test]
fn json_username_match_is_found() {
  let m = manifest(
    r#"{
      "status_gate": {"body_signals_allowed_status": [200]},
      "signals": [
        {"id":"s","outcome":"hit","weight":0.35,"kind":"status","match":{"codes":[200]}},
        {"id":"j","outcome":"hit","weight":0.65,"kind":"json_path","path":"$.username","op":"equals_username"}
      ]
    }"#,
  );
  let body = r#"{"username":"alice","id":7}"#;
  assert_eq!(verdict(&m, &response(200, body)), Verdict::Found);
}

#[test]
fn status_gated_5xx_is_uncertain() {
  let m = manifest(
    r#"{
      "status_gate": {"body_signals_allowed_status": [200,404]},
      "signals": [
        {"id":"s","outcome":"hit","weight":0.9,"kind":"status","match":{"codes":[200]}},
        {"id":"err","outcome":"miss","weight":1.0,"kind":"body_substring","value":"not found"}
      ]
    }"#,
  );
  assert_eq!(
    verdict(&m, &response(502, "bad gateway")),
    Verdict::Uncertain
  );
}

#[test]
fn captcha_body_is_blocked() {
  let m = manifest(
    r#"{
      "signals": [
        {"id":"hit","outcome":"hit","weight":0.9,"kind":"status","match":{"ranges":[[200,299]]}}
      ],
      "block_signals": [
        {"id":"captcha","kind":"body_regex","pattern":"(?i)verify you are human","classify_as":"captcha"}
      ]
    }"#,
  );
  let detector = Detector::new(&m.defaults);
  let result = detector.evaluate(
    &m.sites[0],
    "alice",
    "alice",
    "https://site.test/alice",
    &response(200, "<h1>Please verify you are human</h1>"),
    None,
  );
  assert_eq!(result.verdict, Verdict::Captcha);
}

#[test]
fn soft_404_control_demotes_to_not_found() {
  let m = manifest(STATUS_SITE);
  let detector = Detector::new(&m.defaults);
  let primary = response(200, "generic");
  let control = response(200, "generic");
  let result = detector.evaluate(
    &m.sites[0],
    "alice",
    "alice",
    "https://site.test/alice",
    &primary,
    Some(ControlInput {
      response: &control,
      username_for_url: "mycroftabsentzzz",
      username_raw: "mycroftabsentzzz",
    }),
  );
  assert_eq!(result.verdict, Verdict::NotFound);
}

#[test]
fn distinct_control_keeps_found() {
  let m = manifest(STATUS_SITE);
  let detector = Detector::new(&m.defaults);
  let primary = response(200, "alice profile");
  let control = response(404, "not found");
  let result = detector.evaluate(
    &m.sites[0],
    "alice",
    "alice",
    "https://site.test/alice",
    &primary,
    Some(ControlInput {
      response: &control,
      username_for_url: "mycroftabsentzzz",
      username_raw: "mycroftabsentzzz",
    }),
  );
  assert_eq!(result.verdict, Verdict::Found);
}

fn manifest_with_global_waf() -> Manifest {
  let json = r#"{
    "manifest_version": 1,
    "manifest_id": "test",
    "defaults": {
      "block_signals": [
        {"id":"waf_px","kind":"body_substring","value":"perimeterxIdentifiers","classify_as":"blocked"}
      ]
    },
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
  }"#;
  parse_manifest_str(json).expect("valid test manifest")
}

#[test]
fn global_waf_body_on_2xx_does_not_block() {
  let m = manifest_with_global_waf();
  let body = "<html>...window.perimeterxIdentifiers...alice profile</html>";
  assert_eq!(verdict(&m, &response(200, body)), Verdict::Found);
}

#[test]
fn global_waf_body_on_non_2xx_still_blocks() {
  let m = manifest_with_global_waf();
  let body = "<html>...window.perimeterxIdentifiers...</html>";
  assert_eq!(verdict(&m, &response(403, body)), Verdict::Blocked);
}
