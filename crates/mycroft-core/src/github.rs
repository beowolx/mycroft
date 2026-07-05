#![allow(
  clippy::module_name_repetitions,
  reason = "these names are part of the public report schema"
)]

use std::collections::{BTreeMap, BTreeSet};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use scraper::{Html, Selector};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tokio_util::sync::CancellationToken;

use mycroft_manifest::{HttpMethod, RedirectPolicy};

use crate::config::RuntimeConfig;
use crate::error::{NetworkConfigError, NetworkError};
use crate::net::{
  HttpExecutor, PreparedRequest, ProbeResponse, ReqwestHttpExecutor, Url,
};
use crate::result::ScanId;
use crate::username::Username;
use crate::util::now_rfc3339;

pub const GITHUB_SCHEMA_VERSION: &str = "mycroft.github.v1";

const DEFAULT_API_BASE_URL: &str = "https://api.github.com";
const DEFAULT_REPO_LIMIT: usize = 100;
const DEFAULT_SIMILAR_LIMIT: usize = 10;
const DEFAULT_FRIEND_LIMIT: usize = 20;
const PAGE_SIZE: usize = 100;
const PUBLIC_NOREPLY_DOMAIN: &str = "@users.noreply.github.com";

#[derive(Clone, Debug)]
pub struct GithubOptions {
  pub base_url: String,
  pub web_base_url: String,
  pub token: Option<String>,
  pub repo_limit: usize,
  pub similar_limit: usize,
  pub friend_limit: usize,
}

impl Default for GithubOptions {
  fn default() -> Self {
    Self {
      base_url: std::env::var("MYCROFT_GITHUB_API_BASE")
        .unwrap_or_else(|_| DEFAULT_API_BASE_URL.to_string()),
      web_base_url: std::env::var("MYCROFT_GITHUB_WEB_BASE")
        .unwrap_or_else(|_| "https://github.com".to_string()),
      token: None,
      repo_limit: DEFAULT_REPO_LIMIT,
      similar_limit: DEFAULT_SIMILAR_LIMIT,
      friend_limit: DEFAULT_FRIEND_LIMIT,
    }
  }
}

#[derive(Debug, thiserror::Error)]
pub enum GithubError {
  #[error("invalid GitHub API base URL: {0}")]
  InvalidBaseUrl(String),
  #[error("network configuration error: {0}")]
  NetworkConfig(#[from] NetworkConfigError),
  #[error("GitHub enrichment was interrupted")]
  Interrupted,
}

#[derive(Clone, Debug, Serialize)]
pub struct GithubBatchReport {
  pub schema_version: String,
  pub generated_at: String,
  pub users: Vec<GithubUserReport>,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct GithubUserReport {
  pub username: String,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub profile: Option<GithubProfile>,
  pub repositories: GithubRepositorySummary,
  pub gists: u64,
  #[serde(skip_serializing_if = "Vec::is_empty")]
  pub organizations: Vec<GithubOrganization>,
  #[serde(skip_serializing_if = "Vec::is_empty")]
  pub social_accounts: Vec<GithubSocialAccount>,
  #[serde(skip_serializing_if = "Vec::is_empty")]
  pub ssh_keys: Vec<GithubSshKey>,
  #[serde(skip_serializing_if = "Vec::is_empty")]
  pub friends: Vec<GithubRelatedUser>,
  #[serde(skip_serializing_if = "Vec::is_empty")]
  pub similar_users: Vec<GithubRelatedUser>,
  #[serde(skip_serializing_if = "Vec::is_empty")]
  pub commit_emails: Vec<GithubCommitEmail>,
  #[serde(skip_serializing_if = "Vec::is_empty")]
  pub commit_names: Vec<GithubCommitName>,
  #[serde(skip_serializing_if = "Vec::is_empty")]
  pub errors: Vec<GithubErrorInfo>,
}

#[derive(Clone, Debug, Serialize)]
pub struct GithubProfile {
  pub login: String,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub id: Option<u64>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub name: Option<String>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub company: Option<String>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub blog: Option<String>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub location: Option<String>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub email: Option<String>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub bio: Option<String>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub twitter_username: Option<String>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub public_repos: Option<u64>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub public_gists: Option<u64>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub followers: Option<u64>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub following: Option<u64>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub created_at: Option<String>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub updated_at: Option<String>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub avatar_url: Option<String>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub html_url: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct GithubRepositorySummary {
  pub total_public: u64,
  pub sources: u64,
  pub forks: u64,
  pub archived: u64,
  pub mirrors: u64,
  pub templates: u64,
  #[serde(skip_serializing_if = "Vec::is_empty")]
  pub sampled_repositories: Vec<GithubRepository>,
}

#[allow(
  clippy::struct_excessive_bools,
  reason = "repository booleans mirror GitHub's public repository flags"
)]
#[derive(Clone, Debug, Serialize)]
pub struct GithubRepository {
  pub name: String,
  pub full_name: String,
  pub fork: bool,
  pub archived: bool,
  pub mirror: bool,
  pub template: bool,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub html_url: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct GithubOrganization {
  pub login: String,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub html_url: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct GithubSocialAccount {
  pub provider: String,
  pub url: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct GithubSshKey {
  pub id: u64,
  pub key: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct GithubRelatedUser {
  pub login: String,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub id: Option<u64>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub name: Option<String>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub html_url: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct GithubCommitEmail {
  pub email: String,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub name: Option<String>,
  pub count: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct GithubCommitName {
  pub name: String,
  pub count: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct GithubErrorInfo {
  pub stage: String,
  pub message: String,
}

/// Enriches username scan results with public GitHub profile intelligence.
///
/// # Errors
///
/// Returns an error when the GitHub API base URL is invalid, the HTTP executor
/// cannot be configured, or the cancellation token has already been cancelled.
pub async fn enrich_github(
  usernames: &[Username],
  runtime: &RuntimeConfig,
  options: GithubOptions,
  cancel: CancellationToken,
) -> Result<GithubBatchReport, GithubError> {
  let client = GithubClient::new(runtime, options)?;
  let mut users = Vec::with_capacity(usernames.len());

  for username in usernames {
    if cancel.is_cancelled() {
      return Err(GithubError::Interrupted);
    }
    users.push(client.enrich_user(username, &cancel).await);
  }

  Ok(GithubBatchReport {
    schema_version: GITHUB_SCHEMA_VERSION.to_string(),
    generated_at: now_rfc3339(),
    users,
  })
}

struct GithubClient {
  executor: ReqwestHttpExecutor,
  base_url: Url,
  web_base_url: Url,
  timeout: std::time::Duration,
  max_body_bytes: usize,
  token: Option<String>,
  repo_limit: usize,
  similar_limit: usize,
  friend_limit: usize,
}

impl GithubClient {
  fn new(
    runtime: &RuntimeConfig,
    options: GithubOptions,
  ) -> Result<Self, GithubError> {
    let executor = ReqwestHttpExecutor::new(runtime)?;
    let base_url = Url::parse(&options.base_url)
      .map_err(|e| GithubError::InvalidBaseUrl(e.to_string()))?;
    let web_base_url = Url::parse(&options.web_base_url)
      .map_err(|e| GithubError::InvalidBaseUrl(e.to_string()))?;

    Ok(Self {
      executor,
      base_url,
      web_base_url,
      timeout: runtime.timeouts.request_timeout,
      max_body_bytes: runtime.max_body_bytes_hard_cap,
      token: options.token.filter(|token| !token.trim().is_empty()),
      repo_limit: options.repo_limit,
      similar_limit: options.similar_limit,
      friend_limit: options.friend_limit,
    })
  }

  async fn enrich_user(
    &self,
    username: &Username,
    cancel: &CancellationToken,
  ) -> GithubUserReport {
    let username = username.as_str();
    let mut report = GithubUserReport {
      username: username.to_string(),
      ..GithubUserReport::default()
    };

    let profile = match self.fetch_profile(username).await {
      Ok(profile) => profile,
      Err(error) => {
        report.push_error("profile", error);
        return report;
      }
    };

    report.gists = profile.public_gists.unwrap_or(0);
    report.repositories.total_public = profile.public_repos.unwrap_or(0);
    report.profile = Some(GithubProfile::from(profile));

    if cancel.is_cancelled() {
      report.push_error("interrupted", GithubCallError::interrupted());
      return report;
    }

    let repo_counts = report.record(
      "repository_counts",
      self.fetch_repository_counts(username).await.map(Some),
      None,
    );

    let repos = report.record(
      "repositories",
      self.fetch_repositories(username).await,
      Vec::new(),
    );
    report.repositories = summarize_repositories(
      &repos,
      report.repositories.total_public,
      repo_counts,
      self.repo_limit,
    );

    let organizations = report.record(
      "organizations",
      self.fetch_organizations(username).await,
      Vec::new(),
    );
    report.organizations =
      organizations.into_iter().map(GithubOrganization::from).collect();

    report.ssh_keys = report.record(
      "ssh_keys",
      self.fetch_ssh_keys(username).await,
      Vec::new(),
    );

    report.friends = report.record(
      "friends",
      self.fetch_friends(username).await,
      Vec::new(),
    );

    report.similar_users = report.record(
      "similar_users",
      self.fetch_similar_users(username).await,
      Vec::new(),
    );

    let identities = report.record(
      "commits",
      self.fetch_commit_identities(&repos).await,
      CommitIdentities::default(),
    );
    report.commit_emails = identities.emails;
    report.commit_names = identities.names;

    report
  }

  async fn fetch_profile(
    &self,
    username: &str,
  ) -> Result<ApiProfile, GithubCallError> {
    let name = self.fetch_profile_name(username).await?;
    let mut profile: ApiProfile = self
      .get_json(
        vec!["users".to_string(), username.to_string()],
        Vec::new(),
        "profile",
      )
      .await?;
    profile.name = name.or(profile.name);
    Ok(profile)
  }

  async fn fetch_profile_name(
    &self,
    username: &str,
  ) -> Result<Option<String>, GithubCallError> {
    let text = self
      .get_web_text(vec![username.to_string()], Vec::new(), "profile_html")
      .await?;
    extract_first_text(
      &text,
      "span.p-name.vcard-fullname.d-block.overflow-hidden",
      "profile name",
    )
  }

  async fn fetch_repository_counts(
    &self,
    username: &str,
  ) -> Result<RepositoryCounts, GithubCallError> {
    let forks = self.fetch_repository_count(username, "fork").await?;
    let sources = self.fetch_repository_count(username, "source").await?;
    let archived = self.fetch_repository_count(username, "archived").await?;
    let mirrors = self.fetch_repository_count(username, "mirror").await?;
    let templates = self.fetch_repository_count(username, "template").await?;

    Ok(RepositoryCounts {
      sources,
      forks,
      archived,
      mirrors,
      templates,
    })
  }

  async fn fetch_repository_count(
    &self,
    username: &str,
    kind: &str,
  ) -> Result<u64, GithubCallError> {
    let text = self
      .get_web_text(
        vec![username.to_string()],
        vec![
          ("tab", "repositories".to_string()),
          ("q", String::new()),
          ("type", kind.to_string()),
          ("language", String::new()),
          ("sort", String::new()),
        ],
        "repository_count",
      )
      .await?;
    let raw = extract_first_text(
      &text,
      "div.user-repo-search-results-summary.TableObject-item.TableObject-item--primary.v-align-top strong",
      "repository count",
    )?
    .unwrap_or_else(|| "0".to_string());
    parse_count(&raw)
  }

  async fn fetch_repositories(
    &self,
    username: &str,
  ) -> Result<Vec<ApiRepository>, GithubCallError> {
    let mut repos = Vec::new();
    let mut page = 1usize;
    loop {
      let query = vec![
        ("per_page", PAGE_SIZE.to_string()),
        ("page", page.to_string()),
      ];
      let page_result = self
        .get_json_page::<Vec<ApiRepository>>(
          vec![
            "users".to_string(),
            username.to_string(),
            "repos".to_string(),
          ],
          query,
          "repositories",
        )
        .await?;
      let page_repos = page_result.value;
      let page_was_empty = page_repos.is_empty();
      repos.extend(page_repos);
      if page_was_empty
        || !page_result.has_next
        || repos.len() >= self.repo_limit
      {
        repos.truncate(self.repo_limit);
        return Ok(repos);
      }
      page += 1;
    }
  }

  async fn fetch_organizations(
    &self,
    username: &str,
  ) -> Result<Vec<ApiOrganization>, GithubCallError> {
    self
      .get_json(
        vec![
          "users".to_string(),
          username.to_string(),
          "orgs".to_string(),
        ],
        Vec::new(),
        "organizations",
      )
      .await
  }

  async fn fetch_ssh_keys(
    &self,
    username: &str,
  ) -> Result<Vec<GithubSshKey>, GithubCallError> {
    let text = self
      .get_web_text(vec![format!("{username}.keys")], Vec::new(), "ssh_keys")
      .await?;
    Ok(
      text
        .lines()
        .filter(|line| line.starts_with("ssh-rsa "))
        .enumerate()
        .map(|(index, line)| GithubSshKey {
          id: u64::try_from(index.saturating_add(1)).unwrap_or(u64::MAX),
          key: line.to_string(),
        })
        .collect(),
    )
  }

  async fn fetch_friends(
    &self,
    username: &str,
  ) -> Result<Vec<GithubRelatedUser>, GithubCallError> {
    let followers = self.fetch_friend_names(username, "followers").await?;
    let following = self.fetch_friend_names(username, "following").await?;
    let following: BTreeSet<String> = following.into_iter().collect();
    let friends = followers
      .into_iter()
      .filter(|login| following.contains(login))
      .take(self.friend_limit)
      .map(|name| GithubRelatedUser {
        login: name.clone(),
        id: None,
        name: Some(name),
        html_url: None,
      })
      .collect();

    Ok(friends)
  }

  async fn fetch_friend_names(
    &self,
    username: &str,
    tab: &str,
  ) -> Result<Vec<String>, GithubCallError> {
    let mut names = Vec::new();
    let mut page = 1usize;

    loop {
      let text = self
        .get_web_text(
          vec![username.to_string()],
          vec![("tab", tab.to_string()), ("page", page.to_string())],
          tab,
        )
        .await?;
      let page_names =
        extract_texts(&text, "span.Link--primary", "friend names")?;
      if page_names.is_empty() {
        return Ok(names);
      }
      names.extend(page_names);
      page += 1;
    }
  }

  async fn fetch_similar_users(
    &self,
    username: &str,
  ) -> Result<Vec<GithubRelatedUser>, GithubCallError> {
    let response: ApiSearchUsers = self
      .get_json(
        vec!["search".to_string(), "users".to_string()],
        vec![("q", username.to_string())],
        "similar_users",
      )
      .await?;
    let mut similar = Vec::new();

    for item in response
      .items
      .into_iter()
      .filter(|item| !item.login.eq_ignore_ascii_case(username))
      .take(self.similar_limit)
    {
      let name = self.fetch_profile_name(&item.login).await.ok().flatten();
      similar.push(GithubRelatedUser {
        login: item.login,
        id: item.id,
        name,
        html_url: item.html_url,
      });
    }

    Ok(similar)
  }

  async fn fetch_commit_identities(
    &self,
    repos: &[ApiRepository],
  ) -> Result<CommitIdentities, GithubCallError> {
    let mut email_counts: BTreeMap<String, EmailAccumulator> = BTreeMap::new();
    let mut name_counts: BTreeMap<String, u64> = BTreeMap::new();

    for repo in repos.iter().filter(|repo| !repo.fork).take(self.repo_limit) {
      let repo = repo.clone();
      let timeout = self.timeout;
      let history =
        tokio::task::spawn_blocking(move || collect_git_history(repo, timeout))
          .await
          .map_err(|e| {
            GithubCallError::internal(&format!("git history task failed: {e}"))
          })??;

      for author in history {
        if !author.name.is_empty() {
          *name_counts.entry(author.name.clone()).or_default() += 1;
        }
        if author.email.is_empty() || is_private_github_email(&author.email) {
          continue;
        }
        let entry = email_counts.entry(author.email).or_insert_with(|| {
          EmailAccumulator {
            name: non_empty(author.name),
            count: 0,
          }
        });
        entry.count += 1;
      }
    }

    Ok(CommitIdentities {
      emails: sorted_email_counts(email_counts),
      names: sorted_name_counts(name_counts),
    })
  }

  async fn get_json<T>(
    &self,
    path: Vec<String>,
    query: Vec<(&str, String)>,
    stage: &str,
  ) -> Result<T, GithubCallError>
  where
    T: DeserializeOwned,
  {
    Ok(self.get_json_page(path, query, stage).await?.value)
  }

  async fn get_json_page<T>(
    &self,
    path: Vec<String>,
    query: Vec<(&str, String)>,
    stage: &str,
  ) -> Result<Page<T>, GithubCallError>
  where
    T: DeserializeOwned,
  {
    let url = self.api_url(&path, &query)?;
    let response = self.execute_api(url).await?;
    if !(200..300).contains(&response.status) {
      return Err(GithubCallError::status(stage, &response));
    }
    let value = serde_json::from_slice::<T>(&response.body)
      .map_err(|e| GithubCallError::parse(stage, &e.to_string()))?;
    Ok(Page {
      value,
      has_next: has_next_link(&response),
    })
  }

  async fn get_web_text(
    &self,
    path: Vec<String>,
    query: Vec<(&str, String)>,
    stage: &str,
  ) -> Result<String, GithubCallError> {
    let url = self.web_url(&path, &query)?;
    let response = self.execute_web(url).await?;
    if !(200..300).contains(&response.status) {
      return Err(GithubCallError::status(stage, &response));
    }
    Ok(response.body_text().into_owned())
  }

  async fn execute_api(
    &self,
    url: Url,
  ) -> Result<ProbeResponse, GithubCallError> {
    self.execute(url, self.api_headers()).await
  }

  async fn execute_web(
    &self,
    url: Url,
  ) -> Result<ProbeResponse, GithubCallError> {
    let headers = vec![(
      "Accept".to_string(),
      "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        .to_string(),
    )];
    self.execute(url, headers).await
  }

  fn api_headers(&self) -> Vec<(String, String)> {
    let mut headers = vec![(
      "Accept".to_string(),
      "application/vnd.github+json".to_string(),
    )];
    if let Some(token) = &self.token {
      headers.push(("Authorization".to_string(), format!("Bearer {token}")));
    }
    headers
  }

  async fn execute(
    &self,
    url: Url,
    headers: Vec<(String, String)>,
  ) -> Result<ProbeResponse, GithubCallError> {
    let request = PreparedRequest {
      method: HttpMethod::Get,
      url,
      headers,
      body: None,
      redirect_policy: RedirectPolicy::default(),
      timeout: self.timeout,
      max_body_bytes: self.max_body_bytes,
      idempotent: true,
    };
    self
      .executor
      .execute(request)
      .await
      .map_err(|e| GithubCallError::network(&e))
  }

  fn api_url(
    &self,
    path: &[String],
    query: &[(&str, String)],
  ) -> Result<Url, GithubCallError> {
    Self::url_from_base(&self.base_url, path, query)
  }

  fn web_url(
    &self,
    path: &[String],
    query: &[(&str, String)],
  ) -> Result<Url, GithubCallError> {
    Self::url_from_base(&self.web_base_url, path, query)
  }

  fn url_from_base(
    base_url: &Url,
    path: &[String],
    query: &[(&str, String)],
  ) -> Result<Url, GithubCallError> {
    let mut url = base_url.clone();
    {
      let mut segments = url.path_segments_mut().map_err(|()| {
        GithubCallError::internal("GitHub base URL cannot be a base")
      })?;
      for segment in path {
        segments.push(segment);
      }
    }
    if !query.is_empty() {
      let mut pairs = url.query_pairs_mut();
      for (key, value) in query {
        pairs.append_pair(key, value);
      }
    }
    Ok(url)
  }
}

impl GithubUserReport {
  fn push_error(&mut self, stage: &str, error: GithubCallError) {
    self.errors.push(GithubErrorInfo {
      stage: stage.to_string(),
      message: error.message,
    });
  }

  /// Unwraps a stage result, recording the error under `stage` and falling back
  /// to `default` when the call failed.
  fn record<T>(
    &mut self,
    stage: &str,
    result: Result<T, GithubCallError>,
    default: T,
  ) -> T {
    match result {
      Ok(value) => value,
      Err(error) => {
        self.push_error(stage, error);
        default
      }
    }
  }
}

#[derive(Debug)]
struct GithubCallError {
  message: String,
}

impl GithubCallError {
  fn network(error: &NetworkError) -> Self {
    Self {
      message: error.to_string(),
    }
  }

  fn status(stage: &str, response: &ProbeResponse) -> Self {
    let body = response.body_text();
    let detail = body.trim();
    let message = if detail.is_empty() {
      format!("{stage} returned HTTP {}", response.status)
    } else {
      format!("{stage} returned HTTP {}: {detail}", response.status)
    };
    Self { message }
  }

  fn parse(stage: &str, error: &str) -> Self {
    Self {
      message: format!("{stage} response was not valid JSON: {error}"),
    }
  }

  fn internal(message: &str) -> Self {
    Self {
      message: message.to_string(),
    }
  }

  fn io(action: &str, error: &std::io::Error) -> Self {
    let message = if error.kind() == std::io::ErrorKind::NotFound {
      format!("{action}: git executable was not found")
    } else {
      format!("{action}: {error}")
    };
    Self { message }
  }

  fn interrupted() -> Self {
    Self::internal("GitHub enrichment was interrupted")
  }
}

struct Page<T> {
  value: T,
  has_next: bool,
}

#[derive(Clone, Copy)]
struct RepositoryCounts {
  sources: u64,
  forks: u64,
  archived: u64,
  mirrors: u64,
  templates: u64,
}

impl RepositoryCounts {
  const fn total(self) -> u64 {
    self.sources + self.forks + self.archived + self.mirrors + self.templates
  }
}

#[derive(Default)]
struct CommitIdentities {
  emails: Vec<GithubCommitEmail>,
  names: Vec<GithubCommitName>,
}

struct EmailAccumulator {
  name: Option<String>,
  count: u64,
}

#[derive(Deserialize)]
struct ApiProfile {
  login: String,
  id: Option<u64>,
  name: Option<String>,
  company: Option<String>,
  blog: Option<String>,
  location: Option<String>,
  email: Option<String>,
  bio: Option<String>,
  twitter_username: Option<String>,
  public_repos: Option<u64>,
  public_gists: Option<u64>,
  followers: Option<u64>,
  following: Option<u64>,
  created_at: Option<String>,
  updated_at: Option<String>,
  avatar_url: Option<String>,
  html_url: Option<String>,
}

impl From<ApiProfile> for GithubProfile {
  fn from(profile: ApiProfile) -> Self {
    Self {
      login: profile.login,
      id: profile.id,
      name: profile.name,
      company: empty_to_none(profile.company),
      blog: empty_to_none(profile.blog),
      location: empty_to_none(profile.location),
      email: empty_to_none(profile.email),
      bio: empty_to_none(profile.bio),
      twitter_username: empty_to_none(profile.twitter_username),
      public_repos: profile.public_repos,
      public_gists: profile.public_gists,
      followers: profile.followers,
      following: profile.following,
      created_at: profile.created_at,
      updated_at: profile.updated_at,
      avatar_url: profile.avatar_url,
      html_url: profile.html_url,
    }
  }
}

#[derive(Clone, Deserialize)]
struct ApiRepository {
  name: String,
  full_name: String,
  #[serde(default)]
  fork: bool,
  #[serde(default)]
  archived: bool,
  #[serde(default)]
  is_template: bool,
  mirror_url: Option<String>,
  clone_url: Option<String>,
  html_url: Option<String>,
}

impl From<&ApiRepository> for GithubRepository {
  fn from(repo: &ApiRepository) -> Self {
    Self {
      name: repo.name.clone(),
      full_name: repo.full_name.clone(),
      fork: repo.fork,
      archived: repo.archived,
      mirror: repo.mirror_url.is_some(),
      template: repo.is_template,
      html_url: repo.html_url.clone(),
    }
  }
}

#[derive(Deserialize)]
struct ApiOrganization {
  login: String,
  html_url: Option<String>,
}

impl From<ApiOrganization> for GithubOrganization {
  fn from(org: ApiOrganization) -> Self {
    Self {
      login: org.login,
      html_url: org.html_url,
    }
  }
}

#[derive(Deserialize)]
struct ApiSearchUsers {
  items: Vec<ApiSearchUser>,
}

#[derive(Deserialize)]
struct ApiSearchUser {
  login: String,
  id: Option<u64>,
  html_url: Option<String>,
}

struct GitCommitAuthor {
  name: String,
  email: String,
}

fn collect_git_history(
  repo: ApiRepository,
  timeout: Duration,
) -> Result<Vec<GitCommitAuthor>, GithubCallError> {
  let Some(clone_url) = repo.clone_url else {
    return Ok(Vec::new());
  };
  let repo_path = temp_repo_path()?;
  let cloned = clone_repository(&clone_url, &repo_path, timeout)?;
  if !cloned {
    remove_repo_dir(&repo_path);
    return Ok(Vec::new());
  }
  let history = read_git_history(&repo_path);
  remove_repo_dir(&repo_path);
  history
}

fn temp_repo_path() -> Result<std::path::PathBuf, GithubCallError> {
  let base = std::env::temp_dir().join("mycroft-github");
  std::fs::create_dir_all(&base).map_err(|e| {
    GithubCallError::io("create GitHub clone temp directory", &e)
  })?;
  Ok(base.join(ScanId::random().0))
}

fn clone_repository(
  clone_url: &str,
  repo_path: &std::path::Path,
  timeout: Duration,
) -> Result<bool, GithubCallError> {
  let mut command = Command::new("git");
  command
    .arg("clone")
    .arg("--quiet")
    .arg("--depth")
    .arg("1")
    .arg(clone_url)
    .arg(repo_path)
    .stdout(Stdio::null())
    .stderr(Stdio::null());
  run_status_with_timeout(&mut command, timeout)
}

fn run_status_with_timeout(
  command: &mut Command,
  timeout: Duration,
) -> Result<bool, GithubCallError> {
  let mut child = command
    .spawn()
    .map_err(|e| GithubCallError::io("spawn git clone", &e))?;
  let started = Instant::now();

  loop {
    if let Some(status) = child
      .try_wait()
      .map_err(|e| GithubCallError::io("wait for git clone", &e))?
    {
      return Ok(status.success());
    }
    if started.elapsed() >= timeout {
      let _ = child.kill();
      let _ = child.wait();
      return Ok(false);
    }
    thread::sleep(Duration::from_millis(50));
  }
}

fn read_git_history(
  repo_path: &std::path::Path,
) -> Result<Vec<GitCommitAuthor>, GithubCallError> {
  let output = Command::new("git")
    .arg("-C")
    .arg(repo_path)
    .arg("log")
    .arg("--all")
    .arg("--format=%an|%ae")
    .output()
    .map_err(|e| GithubCallError::io("read git commit history", &e))?;
  if !output.status.success() {
    return Ok(Vec::new());
  }
  Ok(parse_git_history(&String::from_utf8_lossy(&output.stdout)))
}

fn parse_git_history(raw: &str) -> Vec<GitCommitAuthor> {
  raw
    .lines()
    .filter_map(|line| {
      let (name, email) = line.split_once('|')?;
      Some(GitCommitAuthor {
        name: name.trim().to_string(),
        email: email.trim().to_string(),
      })
    })
    .collect()
}

fn remove_repo_dir(repo_path: &std::path::Path) {
  let _ = std::fs::remove_dir_all(repo_path);
}

fn summarize_repositories(
  repos: &[ApiRepository],
  total_public: u64,
  repository_counts: Option<RepositoryCounts>,
  repo_limit: usize,
) -> GithubRepositorySummary {
  let mut summary = GithubRepositorySummary {
    total_public,
    ..GithubRepositorySummary::default()
  };

  if let Some(counts) = repository_counts {
    summary.total_public = counts.total();
    summary.sources = counts.sources;
    summary.forks = counts.forks;
    summary.archived = counts.archived;
    summary.mirrors = counts.mirrors;
    summary.templates = counts.templates;
  } else {
    for repo in repos {
      if repo.fork {
        summary.forks += 1;
      } else {
        summary.sources += 1;
      }
      if repo.archived {
        summary.archived += 1;
      }
      if repo.mirror_url.is_some() {
        summary.mirrors += 1;
      }
      if repo.is_template {
        summary.templates += 1;
      }
    }
  }

  summary.sampled_repositories = repos
    .iter()
    .take(repo_limit)
    .map(GithubRepository::from)
    .collect();
  summary
}

fn extract_first_text(
  html: &str,
  selector: &str,
  label: &str,
) -> Result<Option<String>, GithubCallError> {
  Ok(extract_texts(html, selector, label)?.into_iter().next())
}

fn extract_texts(
  html: &str,
  selector: &str,
  label: &str,
) -> Result<Vec<String>, GithubCallError> {
  let selector = Selector::parse(selector).map_err(|error| {
    GithubCallError::internal(&format!("invalid {label} selector: {error:?}"))
  })?;
  let document = Html::parse_document(html);
  Ok(
    document
      .select(&selector)
      .filter_map(|node| {
        let text = node.text().collect::<String>().trim().to_string();
        if text.is_empty() { None } else { Some(text) }
      })
      .collect(),
  )
}

fn parse_count(raw: &str) -> Result<u64, GithubCallError> {
  let digits = raw.chars().filter(char::is_ascii_digit).collect::<String>();
  if digits.is_empty() {
    return Ok(0);
  }
  digits.parse::<u64>().map_err(|error| {
    GithubCallError::internal(&format!("invalid GitHub count {raw:?}: {error}"))
  })
}

fn sorted_email_counts(
  counts: BTreeMap<String, EmailAccumulator>,
) -> Vec<GithubCommitEmail> {
  let mut emails: Vec<GithubCommitEmail> = counts
    .into_iter()
    .map(|(email, count)| GithubCommitEmail {
      email,
      name: count.name,
      count: count.count,
    })
    .collect();
  emails.sort_by(|left, right| {
    right
      .count
      .cmp(&left.count)
      .then_with(|| left.email.cmp(&right.email))
  });
  emails
}

fn sorted_name_counts(counts: BTreeMap<String, u64>) -> Vec<GithubCommitName> {
  let mut names: Vec<GithubCommitName> = counts
    .into_iter()
    .map(|(name, count)| GithubCommitName { name, count })
    .collect();
  names.sort_by(|left, right| {
    right
      .count
      .cmp(&left.count)
      .then_with(|| left.name.cmp(&right.name))
  });
  names
}

fn has_next_link(response: &ProbeResponse) -> bool {
  response.header("link").is_some_and(|header| {
    header
      .split(',')
      .any(|part| part.contains("rel=\"next\"") || part.contains("rel=next"))
  })
}

fn is_private_github_email(email: &str) -> bool {
  // `PUBLIC_NOREPLY_DOMAIN` is already lowercase, so match case-insensitively
  // without allocating a lowercased copy of every commit author's email.
  let needle = PUBLIC_NOREPLY_DOMAIN.as_bytes();
  email
    .as_bytes()
    .windows(needle.len())
    .any(|window| window.eq_ignore_ascii_case(needle))
}

fn non_empty(value: String) -> Option<String> {
  (!value.is_empty()).then_some(value)
}

fn empty_to_none(value: Option<String>) -> Option<String> {
  value.and_then(non_empty)
}
