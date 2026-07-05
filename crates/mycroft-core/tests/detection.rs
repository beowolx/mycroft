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

const EMAIL_STATUS_SITE: &str = r#"{
  "status_gate": {"body_signals_allowed_status": [200]},
  "signals": [
    {"id":"email_registered","outcome":"hit","weight":0.97,"kind":"json_path","path":"$.status","op":"equals","value":20},
    {"id":"email_available","outcome":"miss","weight":0.97,"kind":"json_path","path":"$.status","op":"equals","value":1}
  ]
}"#;

#[test]
fn email_account_registered_status_is_found() {
  let m = manifest(EMAIL_STATUS_SITE);
  let body = r#"{"status":20,"errors":{"email":"already registered"}}"#;
  assert_eq!(verdict(&m, &response(200, body)), Verdict::Found);
}

#[test]
fn email_account_available_status_is_not_found() {
  let m = manifest(EMAIL_STATUS_SITE);
  assert_eq!(
    verdict(&m, &response(200, r#"{"status":1}"#)),
    Verdict::NotFound
  );
}

const EMAIL_STATUS_CODE_SITE: &str = r#"{
  "signals": [
    {"id":"profile_exists","outcome":"hit","weight":0.95,"kind":"status","match":{"codes":[200]}},
    {"id":"no_profile","outcome":"miss","weight":0.95,"kind":"status","match":{"codes":[404]}}
  ]
}"#;

#[test]
fn gravatar_style_200_is_found_404_is_not_found() {
  let m = manifest(EMAIL_STATUS_CODE_SITE);
  assert_eq!(verdict(&m, &response(200, "{}")), Verdict::Found);
  assert_eq!(verdict(&m, &response(404, "")), Verdict::NotFound);
}

const EMAIL_USERS_ARRAY_SITE: &str = r#"{
  "status_gate": {"body_signals_allowed_status": [200]},
  "signals": [
    {"id":"account_exists","outcome":"hit","weight":0.9,"kind":"json_path","path":"$.users[0]","op":"exists"},
    {"id":"account_absent","outcome":"miss","weight":0.9,"kind":"body_substring","value":"\"users\":[]"}
  ]
}"#;

#[test]
fn duolingo_style_populated_array_is_found() {
  let m = manifest(EMAIL_USERS_ARRAY_SITE);
  let body = r#"{"users":[{"id":0,"username":""}]}"#;
  assert_eq!(verdict(&m, &response(200, body)), Verdict::Found);
}

#[test]
fn duolingo_style_empty_array_is_not_found() {
  let m = manifest(EMAIL_USERS_ARRAY_SITE);
  assert_eq!(
    verdict(&m, &response(200, r#"{"users":[]}"#)),
    Verdict::NotFound
  );
}

const EMAIL_BOOL_SITE: &str = r#"{
  "status_gate": {"body_signals_allowed_status": [200]},
  "signals": [
    {"id":"email_taken","outcome":"hit","weight":0.95,"kind":"json_path","path":"$.taken","op":"equals","value":true},
    {"id":"email_available","outcome":"miss","weight":0.95,"kind":"json_path","path":"$.taken","op":"equals","value":false}
  ]
}"#;

#[test]
fn twitter_style_taken_bool_is_found_or_not_found() {
  let m = manifest(EMAIL_BOOL_SITE);
  assert_eq!(
    verdict(&m, &response(200, r#"{"taken":true}"#)),
    Verdict::Found
  );
  assert_eq!(
    verdict(&m, &response(200, r#"{"taken":false}"#)),
    Verdict::NotFound
  );
}

const EMAIL_ROOT_ARRAY_SITE: &str = r#"{
  "status_gate": {"body_signals_allowed_status": [200]},
  "signals": [
    {"id":"account_exists","outcome":"hit","weight":0.95,"kind":"json_path","path":"$[0]","op":"exists"},
    {"id":"no_account","outcome":"miss","weight":0.95,"kind":"body_regex","pattern":"^\\s*\\[\\s*\\]\\s*$"}
  ]
}"#;

#[test]
fn adobe_style_populated_root_array_is_found() {
  let m = manifest(EMAIL_ROOT_ARRAY_SITE);
  let body = r#"[{"type":"individual","authenticationMethods":[]}]"#;
  assert_eq!(verdict(&m, &response(200, body)), Verdict::Found);
}

#[test]
fn adobe_style_empty_root_array_is_not_found() {
  let m = manifest(EMAIL_ROOT_ARRAY_SITE);
  assert_eq!(verdict(&m, &response(200, "[]")), Verdict::NotFound);
}

const EMAIL_RECOVERY_SITE: &str = r#"{
  "status_gate": {"body_signals_allowed_status": [200]},
  "signals": [
    {"id":"account_exists","outcome":"hit","weight":0.9,"kind":"json_path","path":"$.status","op":"equals","value":200},
    {"id":"account_absent","outcome":"miss","weight":0.9,"kind":"json_path","path":"$.body.email.error","op":"equals","value":"not_exists"}
  ]
}"#;

#[test]
fn mailru_style_recovery_status_200_is_found() {
  let m = manifest(EMAIL_RECOVERY_SITE);
  let body = r#"{"status":200,"body":{"emails":["a***@mail.ru"]}}"#;
  assert_eq!(verdict(&m, &response(200, body)), Verdict::Found);
}

#[test]
fn mailru_style_not_exists_is_not_found() {
  let m = manifest(EMAIL_RECOVERY_SITE);
  let body = r#"{"status":400,"body":{"email":{"error":"not_exists"}}}"#;
  assert_eq!(verdict(&m, &response(200, body)), Verdict::NotFound);
}

const EMAIL_CODE_SITE: &str = r#"{
  "status_gate": {"body_signals_allowed_status": [200]},
  "signals": [
    {"id":"email_taken","outcome":"hit","weight":0.85,"kind":"json_path","path":"$.code","op":"equals","value":1},
    {"id":"email_available","outcome":"miss","weight":0.9,"kind":"json_path","path":"$.code","op":"equals","value":0}
  ]
}"#;

#[test]
fn xvideos_style_code_1_is_found_code_0_is_not_found() {
  let m = manifest(EMAIL_CODE_SITE);
  assert_eq!(
    verdict(&m, &response(200, r#"{"result":false,"code":1}"#)),
    Verdict::Found
  );
  assert_eq!(
    verdict(&m, &response(200, r#"{"result":true,"code":0}"#)),
    Verdict::NotFound
  );
}

const EMAIL_TRUEFALSE_SITE: &str = r#"{
  "status_gate": {"body_signals_allowed_status": [200]},
  "signals": [
    {"id":"account_exists","outcome":"hit","weight":0.9,"kind":"body_substring","value":"True"},
    {"id":"account_absent","outcome":"miss","weight":0.9,"kind":"body_substring","value":"False"}
  ]
}"#;

#[test]
fn plurk_style_true_is_found_false_is_not_found() {
  let m = manifest(EMAIL_TRUEFALSE_SITE);
  assert_eq!(verdict(&m, &response(200, "True")), Verdict::Found);
  assert_eq!(verdict(&m, &response(200, "False")), Verdict::NotFound);
}
