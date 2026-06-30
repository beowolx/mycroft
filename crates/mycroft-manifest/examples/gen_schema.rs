use mycroft_manifest::schema::Manifest;

fn main() {
  let schema = schemars::schema_for!(Manifest);
  println!(
    "{}",
    serde_json::to_string_pretty(&schema).expect("schema serializes to JSON")
  );
}
