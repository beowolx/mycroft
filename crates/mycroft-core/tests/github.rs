use std::collections::VecDeque;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};

use mycroft_core::config::RuntimeConfig;
use mycroft_core::github::{GithubOptions, enrich_github};
use mycroft_core::{CancellationToken, Username};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[derive(Clone)]
struct Response {
  status: u16,
  body: String,
}

#[tokio::test]
async fn github_enrichment_matches_gitsint_baseline_shape() {
  let git_repo = TestGitRepo::create();
  let repo_body = format!(
    r#"[
      {{"name":"source-one","full_name":"beowolx/source-one","fork":false,"archived":false,"is_template":false,"mirror_url":null,"clone_url":{},"html_url":"https://github.com/beowolx/source-one"}},
      {{"name":"fork-one","full_name":"beowolx/fork-one","fork":true,"archived":false,"is_template":false,"mirror_url":null,"clone_url":"https://github.com/beowolx/fork-one.git","html_url":"https://github.com/beowolx/fork-one"}}
    ]"#,
    serde_json::to_string(&git_repo.clone_url()).expect("clone URL JSON")
  );
  let server = GithubFixture::start(vec![
    (
      "/beowolx",
      Response::html(
        r#"<html><span class="p-name vcard-fullname d-block overflow-hidden">beowulf</span></html>"#,
      ),
    ),
    (
      "/users/beowolx",
      Response::json(
        r#"{
          "login":"beowolx",
          "id":61982523,
          "name":"beowulf",
          "company":null,
          "blog":"https://luiscardoso.dev/",
          "location":"Paris, France",
          "email":null,
          "bio":"Software Engineer",
          "twitter_username":"beowolx",
          "public_repos":2,
          "public_gists":1,
          "followers":2,
          "following":2,
          "created_at":"2020-03-09T15:54:49Z",
          "updated_at":"2026-07-02T08:51:52Z",
          "avatar_url":"https://avatars.githubusercontent.com/u/61982523?v=4",
          "html_url":"https://github.com/beowolx"
        }"#,
      ),
    ),
    (
      "/beowolx?tab=repositories&q=&type=fork&language=&sort=",
      Response::html(repo_count_html(1)),
    ),
    (
      "/beowolx?tab=repositories&q=&type=source&language=&sort=",
      Response::html(repo_count_html(1)),
    ),
    (
      "/beowolx?tab=repositories&q=&type=archived&language=&sort=",
      Response::html(repo_count_html(0)),
    ),
    (
      "/beowolx?tab=repositories&q=&type=mirror&language=&sort=",
      Response::html(repo_count_html(0)),
    ),
    (
      "/beowolx?tab=repositories&q=&type=template&language=&sort=",
      Response::html(repo_count_html(0)),
    ),
    (
      "/users/beowolx/repos?per_page=100&page=1",
      Response::json(repo_body),
    ),
    (
      "/users/beowolx/orgs",
      Response::json(r#"[{"login":"example-org","html_url":"https://github.com/example-org"}]"#),
    ),
    (
      "/beowolx.keys",
      Response::text("ssh-ed25519 AAAAC3NzaIgnored\nssh-rsa AAAAB3NzaCounted\n"),
    ),
    (
      "/beowolx?tab=followers&page=1",
      Response::html(friends_html(["Friend One", "Follower Only"])),
    ),
    (
      "/beowolx?tab=followers&page=2",
      Response::html(""),
    ),
    (
      "/beowolx?tab=following&page=1",
      Response::html(friends_html(["Friend One", "Following Only"])),
    ),
    (
      "/beowolx?tab=following&page=2",
      Response::html(""),
    ),
    (
      "/search/users?q=beowolx",
      Response::json(r#"{"items":[{"login":"beowolx"},{"login":"beowolx2"}]}"#),
    ),
    (
      "/beowolx2",
      Response::html(
        r#"<html><span class="p-name vcard-fullname d-block overflow-hidden">Luis Cardoso</span></html>"#,
      ),
    ),
  ])
  .await;

  let options = GithubOptions {
    base_url: server.base_url(),
    web_base_url: server.base_url(),
    token: None,
    repo_limit: 20,
    similar_limit: 10,
    friend_limit: 10,
  };
  let runtime = RuntimeConfig {
    allow_private_targets: true,
    ..RuntimeConfig::default()
  };
  let usernames = vec![Username::parse("beowolx").expect("valid username")];

  let report =
    enrich_github(&usernames, &runtime, options, CancellationToken::new())
      .await
      .expect("github enrichment completes");

  let user = report.users.first().expect("one user report");
  assert_eq!(user.username, "beowolx");
  assert_eq!(
    user.profile.as_ref().expect("profile").name.as_deref(),
    Some("beowulf")
  );
  assert_eq!(user.repositories.total_public, 2);
  assert_eq!(user.repositories.sources, 1);
  assert_eq!(user.repositories.forks, 1);
  assert_eq!(user.gists, 1);
  assert_eq!(user.ssh_keys.len(), 1);
  assert_eq!(user.organizations[0].login, "example-org");
  assert_eq!(user.social_accounts.len(), 0);
  assert_eq!(user.friends[0].login, "Friend One");
  assert_eq!(user.friends[0].name.as_deref(), Some("Friend One"));
  assert_eq!(user.similar_users[0].login, "beowolx2");
  assert_eq!(user.similar_users[0].name.as_deref(), Some("Luis Cardoso"));
  assert_eq!(user.commit_emails[0].email, "luis@luiscardoso.dev");
  assert_eq!(user.commit_names[0].name, "Luis Cardoso");
  assert_eq!(user.commit_names[0].count, 1);
  assert_eq!(user.errors.len(), 0);
}

impl Response {
  fn ok(body: impl Into<String>) -> Self {
    Self {
      status: 200,
      body: body.into(),
    }
  }

  fn json(body: impl Into<String>) -> Self {
    Self::ok(body)
  }

  fn html(body: impl Into<String>) -> Self {
    Self::ok(body)
  }

  fn text(body: impl Into<String>) -> Self {
    Self::ok(body)
  }
}

fn repo_count_html(count: u64) -> String {
  format!(
    r#"<div class="user-repo-search-results-summary TableObject-item TableObject-item--primary v-align-top"><strong>{count}</strong></div>"#
  )
}

fn friends_html<const N: usize>(names: [&str; N]) -> String {
  names
    .into_iter()
    .map(|name| format!(r#"<span class="Link--primary">{name}</span>"#))
    .collect::<Vec<_>>()
    .join("\n")
}

struct GithubFixture {
  addr: SocketAddr,
  requests: Arc<Mutex<VecDeque<(String, Response)>>>,
}

impl GithubFixture {
  async fn start(routes: Vec<(&'static str, Response)>) -> Self {
    let listener = TcpListener::bind("127.0.0.1:0")
      .await
      .expect("bind fixture");
    let addr = listener.local_addr().expect("fixture address");
    let requests = Arc::new(Mutex::new(
      routes
        .into_iter()
        .map(|(path, response)| (path.to_string(), response))
        .collect::<VecDeque<_>>(),
    ));
    let server_requests = requests.clone();

    tokio::spawn(async move {
      loop {
        let Ok((mut stream, _)) = listener.accept().await else {
          break;
        };
        let routes = server_requests.clone();
        tokio::spawn(async move {
          let mut buf = [0_u8; 4096];
          let Ok(n) = stream.read(&mut buf).await else {
            return;
          };
          let request = String::from_utf8_lossy(&buf[..n]);
          let path = request
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .expect("request target")
            .to_string();
          let response = next_response(&routes, &path);
          let body = response.body;
          let raw = format!(
            "HTTP/1.1 {} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            response.status,
            body.len(),
          );
          let _ = stream.write_all(raw.as_bytes()).await;
        });
      }
    });

    Self { addr, requests }
  }

  fn base_url(&self) -> String {
    format!("http://{}", self.addr)
  }
}

struct TestGitRepo {
  path: PathBuf,
}

impl TestGitRepo {
  fn create() -> Self {
    let path = std::env::temp_dir().join(format!(
      "mycroft-github-test-{}-{}",
      std::process::id(),
      unique_suffix(),
    ));
    fs::create_dir_all(&path).expect("create git fixture directory");
    run_git(&path, ["init", "--quiet"]);
    run_git(&path, ["config", "user.name", "Luis Cardoso"]);
    run_git(&path, ["config", "user.email", "luis@luiscardoso.dev"]);
    fs::write(path.join("README.md"), "fixture\n").expect("write fixture file");
    run_git(&path, ["add", "README.md"]);
    run_git(&path, ["commit", "--quiet", "-m", "initial"]);
    Self { path }
  }

  fn clone_url(&self) -> String {
    self.path.to_string_lossy().into_owned()
  }
}

impl Drop for TestGitRepo {
  fn drop(&mut self) {
    let _ = fs::remove_dir_all(&self.path);
  }
}

fn run_git<const N: usize>(path: &Path, args: [&str; N]) {
  let status = Command::new("git")
    .arg("-C")
    .arg(path)
    .args(args)
    .status()
    .expect("run git fixture command");
  assert!(status.success(), "git fixture command failed");
}

fn unique_suffix() -> u128 {
  std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .expect("system clock")
    .as_nanos()
}

impl Drop for GithubFixture {
  fn drop(&mut self) {
    assert!(
      self.requests.lock().expect("routes lock").is_empty(),
      "not all fixture routes were requested"
    );
  }
}

fn next_response(
  routes: &Arc<Mutex<VecDeque<(String, Response)>>>,
  path: &str,
) -> Response {
  let (expected, response) = {
    let mut routes = routes.lock().expect("routes lock");
    routes.pop_front().expect("unexpected request")
  };
  assert_eq!(path, expected);
  response
}
