use mycroft_manifest::import_catalog::import_catalog;
use mycroft_manifest::{HttpMethod, bundled_manifest, validate_manifest};

#[test]
fn bundled_manifest_loads_and_validates() {
  let manifest = bundled_manifest().expect("bundled manifest parses");
  assert!(manifest.sites.len() > 400);
  validate_manifest(&manifest).expect("bundled manifest validates");
}

#[test]
fn status_code_imports_as_head_with_status_signals() {
  let data = serde_json::json!({
    "GitHub": {
      "errorType": "status_code",
      "url": "https://github.com/{}",
      "urlMain": "https://github.com/",
      "username_claimed": "octocat"
    }
  });
  let manifest = import_catalog(&data, "t", None).expect("import succeeds");
  let site = &manifest.sites[0];
  assert_eq!(site.request.method, HttpMethod::Head);
  assert!(
    site
      .detection
      .signals
      .iter()
      .any(|s| s.id == "status_claimed")
  );
}

#[test]
fn message_imports_as_get_with_body_miss_signal() {
  let data = serde_json::json!({
    "Example": {
      "errorType": "message",
      "errorMsg": "not found",
      "url": "https://example.test/{}",
      "urlMain": "https://example.test/",
      "username_claimed": "x"
    }
  });
  let manifest = import_catalog(&data, "t", None).expect("import succeeds");
  let site = &manifest.sites[0];
  assert_eq!(site.request.method, HttpMethod::Get);
  assert!(
    site
      .detection
      .signals
      .iter()
      .any(|s| s.id == "message_miss_0")
  );
}
