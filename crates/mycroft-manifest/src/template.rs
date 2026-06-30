pub const USERNAME_PLACEHOLDER: &str = "{username}";

#[must_use]
pub fn interpolate(template: &str, encoded_username: &str) -> String {
  template.replace(USERNAME_PLACEHOLDER, encoded_username)
}

#[must_use]
pub fn has_placeholder(template: &str) -> bool {
  template.contains(USERNAME_PLACEHOLDER)
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
pub fn interpolate_json(
  value: &serde_json::Value,
  username: &str,
) -> serde_json::Value {
  map_json_strings(value, &|s| interpolate(s, username))
}

#[cfg(test)]
mod tests {
  use crate::template::{interpolate, interpolate_json};

  #[test]
  fn interpolate_replaces_all_placeholders() {
    let out = interpolate("https://x.test/{username}/{username}", "alice");
    assert_eq!(out, "https://x.test/alice/alice");
  }

  #[test]
  fn interpolate_json_recurses_into_nested_strings() {
    let input = serde_json::json!({
      "query": "name={username}",
      "vars": {"name": "{username}"},
      "list": ["{username}", 1],
    });
    let out = interpolate_json(&input, "bob");
    assert_eq!(out["query"], "name=bob");
    assert_eq!(out["vars"]["name"], "bob");
    assert_eq!(out["list"][0], "bob");
    assert_eq!(out["list"][1], 1);
  }
}
