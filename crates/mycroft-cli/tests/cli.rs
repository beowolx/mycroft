use assert_cmd::Command;
use predicates::prelude::*;

fn mycroft() -> Command {
  Command::cargo_bin("mycroft").expect("binary builds")
}

#[test]
fn completions_bash_emits_script() {
  mycroft()
    .args(["completions", "bash"])
    .assert()
    .success()
    .stdout(predicate::str::contains("_mycroft"));
}

#[test]
fn sites_show_outputs_json() {
  mycroft()
    .args(["sites", "show", "github"])
    .assert()
    .success()
    .stdout(predicate::str::contains("\"id\": \"github\""));
}

#[test]
fn check_help_does_not_include_github_flag() {
  mycroft()
    .args(["check", "--help"])
    .assert()
    .success()
    .stdout(predicate::str::contains("--github").not());
}

#[test]
fn github_help_exposes_dedicated_command() {
  mycroft()
    .args(["github", "--help"])
    .assert()
    .success()
    .stdout(predicate::str::contains(
      "Run GitHub enrichment for one or more usernames.",
    ))
    .stdout(predicate::str::contains("--site").not())
    .stdout(predicate::str::contains("--format"));
}

#[test]
fn unknown_site_is_usage_error() {
  mycroft()
    .args(["sites", "show", "definitely-not-a-real-site"])
    .assert()
    .code(2);
}
