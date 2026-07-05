pub const USERNAME_PLACEHOLDER: &str = "{username}";

pub const EMAIL_PLACEHOLDER: &str = "{email}";
pub const EMAIL_LOCAL_PLACEHOLDER: &str = "{email_local}";
pub const EMAIL_DOMAIN_PLACEHOLDER: &str = "{email_domain}";
pub const EMAIL_MD5_PLACEHOLDER: &str = "{email_md5}";
pub const EMAIL_SHA256_PLACEHOLDER: &str = "{email_sha256}";

pub const EMAIL_PLACEHOLDERS: &[&str] = &[
  EMAIL_PLACEHOLDER,
  EMAIL_LOCAL_PLACEHOLDER,
  EMAIL_DOMAIN_PLACEHOLDER,
  EMAIL_MD5_PLACEHOLDER,
  EMAIL_SHA256_PLACEHOLDER,
];

#[must_use]
pub fn interpolate_vars<K: AsRef<str>>(
  template: &str,
  vars: &[(K, String)],
) -> String {
  let mut out = template.to_string();
  for (placeholder, value) in vars {
    out = out.replace(placeholder.as_ref(), value);
  }
  out
}

#[must_use]
pub fn has_placeholder(template: &str) -> bool {
  template.contains(USERNAME_PLACEHOLDER)
}

#[must_use]
pub fn has_email_placeholder(template: &str) -> bool {
  EMAIL_PLACEHOLDERS.iter().any(|p| template.contains(p))
}

pub const VAR_PREFIX: &str = "{var:";

#[must_use]
pub fn strip_unresolved_vars(template: &str) -> String {
  let mut out = String::with_capacity(template.len());
  let mut rest = template;
  while let Some(start) = rest.find(VAR_PREFIX) {
    out.push_str(&rest[..start]);
    let Some(end) = rest[start..].find('}') else {
      rest = &rest[start..];
      break;
    };
    out.push_str("probe");
    rest = &rest[start + end + 1..];
  }
  out.push_str(rest);
  out
}

#[must_use]
pub fn interpolate_probe(template: &str) -> String {
  let probe: &[(&str, &str)] = &[
    (USERNAME_PLACEHOLDER, "mycroftvalidationuser"),
    (EMAIL_PLACEHOLDER, "mycroftvalidation%40example.com"),
    (EMAIL_LOCAL_PLACEHOLDER, "mycroftvalidation"),
    (EMAIL_DOMAIN_PLACEHOLDER, "example.com"),
    (EMAIL_MD5_PLACEHOLDER, "00000000000000000000000000000000"),
    (
      EMAIL_SHA256_PLACEHOLDER,
      "0000000000000000000000000000000000000000000000000000000000000000",
    ),
  ];
  let mut out = template.to_string();
  for (placeholder, value) in probe {
    out = out.replace(placeholder, value);
  }
  strip_unresolved_vars(&out)
}

#[must_use]
pub fn map_json_strings(
  value: &serde_json::Value,
  f: &impl Fn(&str) -> String,
) -> serde_json::Value {
  use serde_json::Value;
  match value {
    Value::String(s) => Value::String(f(s)),
    Value::Array(items) => {
      Value::Array(items.iter().map(|v| map_json_strings(v, f)).collect())
    }
    Value::Object(map) => Value::Object(
      map
        .iter()
        .map(|(k, v)| (k.clone(), map_json_strings(v, f)))
        .collect(),
    ),
    other => other.clone(),
  }
}

#[must_use]
pub fn interpolate_json_vars<K: AsRef<str>>(
  value: &serde_json::Value,
  vars: &[(K, String)],
) -> serde_json::Value {
  map_json_strings(value, &|s| interpolate_vars(s, vars))
}

#[cfg(test)]
mod tests {
  use crate::template::{interpolate_json_vars, interpolate_vars};

  #[test]
  fn interpolate_json_vars_recurses_into_nested_strings() {
    let input = serde_json::json!({
      "query": "name={username}",
      "vars": {"name": "{username}"},
      "list": ["{username}", 1],
    });
    let vars = vec![("{username}", "bob".to_string())];
    let out = interpolate_json_vars(&input, &vars);
    assert_eq!(out["query"], "name=bob");
    assert_eq!(out["vars"]["name"], "bob");
    assert_eq!(out["list"][0], "bob");
    assert_eq!(out["list"][1], 1);
  }

  #[test]
  fn interpolate_vars_replaces_email_placeholders() {
    let vars = vec![
      ("{email}", "a%40b.com".to_string()),
      ("{email_local}", "a".to_string()),
      ("{email_domain}", "b.com".to_string()),
    ];
    let out = interpolate_vars(
      "https://x.test/?e={email}&u={email_local}@{email_domain}",
      &vars,
    );
    assert_eq!(out, "https://x.test/?e=a%40b.com&u=a@b.com");
  }
}
