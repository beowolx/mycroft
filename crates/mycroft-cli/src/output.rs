use std::borrow::Cow;
use std::fmt::Write as FmtWrite;
use std::io::{self, Write};

use console::Style;
use indicatif::ProgressBar;

use mycroft_core::event::ScanEvent;
use mycroft_core::github::{GithubBatchReport, GithubUserReport};
use mycroft_core::result::{ScanReport, SiteResult, Verdict};

use crate::args::{FormatArg, PrintArg};

pub type Sink = Box<dyn Write + Send>;

pub trait OutputWriter: Send {
  fn on_event(&mut self, event: &ScanEvent) -> io::Result<()>;
  fn finish(&mut self, report: &ScanReport) -> io::Result<()>;
}

pub struct HumanOptions {
  pub print: PrintArg,
  pub verbose: bool,
  pub quiet: bool,
  pub color: bool,
  pub bar: Option<ProgressBar>,
}

#[must_use]
pub fn make_writer(
  format: FormatArg,
  sink: Sink,
  human: HumanOptions,
) -> Box<dyn OutputWriter> {
  match format {
    FormatArg::Human => Box::new(HumanWriter::new(sink, human)),
    FormatArg::Json => Box::new(JsonWriter { sink }),
    FormatArg::Ndjson => Box::new(NdjsonWriter { sink }),
    FormatArg::Csv => Box::new(CsvWriter {
      sink,
      scan_id: String::new(),
    }),
  }
}

pub fn write_github_report(
  format: FormatArg,
  sink: Sink,
  human: HumanOptions,
  report: &GithubBatchReport,
) -> io::Result<()> {
  match format {
    FormatArg::Human => HumanWriter::new(sink, human).finish_github(report),
    FormatArg::Json => write_json_report(sink, report),
    FormatArg::Ndjson => write_ndjson_github_report(sink, report),
    FormatArg::Csv => write_csv_github_report(sink, report),
  }
}

struct HumanWriter {
  sink: Sink,
  print: PrintArg,
  verbose: bool,
  quiet: bool,
  color: bool,
  bar: Option<ProgressBar>,
}

impl OutputWriter for HumanWriter {
  fn on_event(&mut self, event: &ScanEvent) -> io::Result<()> {
    match event {
      ScanEvent::ScanStarted {
        scan_id,
        task_count,
      } if !self.quiet => {
        let line = self.header(&scan_id.to_string(), *task_count);
        self.emit(&line)
      }
      ScanEvent::Result { result } if should_print(result, self.print) => {
        let block = self.render_row(result);
        self.emit(&block)
      }
      _ => Ok(()),
    }
  }

  fn finish(&mut self, report: &ScanReport) -> io::Result<()> {
    if self.quiet {
      return Ok(());
    }
    writeln!(self.sink, "\n{}", self.summary(&report.summary))?;
    Ok(())
  }
}

impl HumanWriter {
  fn new(sink: Sink, human: HumanOptions) -> Self {
    Self {
      sink,
      print: human.print,
      verbose: human.verbose,
      quiet: human.quiet,
      color: human.color,
      bar: human.bar,
    }
  }

  fn paint(&self, style: Style, text: &str) -> String {
    style.force_styling(self.color).apply_to(text).to_string()
  }

  fn header(&self, scan_id: &str, task_count: usize) -> String {
    let id = scan_id.get(..12).unwrap_or(scan_id);
    format!(
      "  {} {}\n",
      self.paint(
        Style::new().bold(),
        &format!("mycroft v{}", env!("CARGO_PKG_VERSION"))
      ),
      self.paint(Style::new().dim(), &format!("· {task_count} checks · {id}")),
    )
  }

  fn render_row(&self, result: &SiteResult) -> String {
    let glyph =
      self.paint(verdict_style(result.verdict), verdict_glyph(result.verdict));
    let name_style = if result.verdict == Verdict::Found {
      Style::new().bold()
    } else {
      Style::new()
    };
    let name = self.paint(
      name_style,
      &format!("{:<22}", truncate(&result.site_name, 22)),
    );
    let detail = self.detail(result);

    let mut block = format!("  {glyph}  {name} {detail}");
    if self.verbose {
      for evidence in &result.evidence {
        block.push('\n');
        block.push_str(&self.paint(
          Style::new().dim(),
          &format!(
            "        {} [{}] {}",
            evidence.signal_id, evidence.weight, evidence.message
          ),
        ));
      }
    }
    block
  }

  fn detail(&self, result: &SiteResult) -> String {
    if let Some(url) = &result.profile_url {
      return url.clone();
    }
    if let Some(error) = &result.error {
      return self.paint(Style::new().red(), &error.message);
    }
    String::new()
  }

  fn summary(&self, s: &mycroft_core::result::ScanSummary) -> String {
    let mut parts = vec![
      self.paint(Style::new().green().bold(), &format!("{} found", s.found)),
      format!("{} not found", s.not_found),
      format!("{} uncertain", s.uncertain),
      format!("{} blocked", s.blocked),
      format!("{} rate-limited", s.rate_limited),
      format!("{} invalid", s.invalid_username),
    ];
    let errors = format!("{} errors", s.errors);
    parts.push(if s.errors > 0 {
      self.paint(Style::new().red(), &errors)
    } else {
      errors
    });
    parts.push(self.paint(Style::new().dim(), &format_elapsed(s.elapsed_ms)));
    format!(
      "  {}",
      parts.join(self.paint(Style::new().dim(), "  ·  ").as_str())
    )
  }

  fn github_report(&self, report: &GithubBatchReport) -> String {
    let mut out = String::new();
    for user in &report.users {
      if !out.is_empty() {
        out.push('\n');
      }
      self.push_github_user(&mut out, user);
    }
    out
  }

  fn finish_github(&mut self, report: &GithubBatchReport) -> io::Result<()> {
    if self.quiet {
      return Ok(());
    }
    let block = self.github_report(report);
    if block.is_empty() {
      return Ok(());
    }
    match self.bar.clone() {
      Some(bar) => bar.suspend(|| writeln!(self.sink, "{block}")),
      None => writeln!(self.sink, "{block}"),
    }
  }

  fn push_github_user(&self, out: &mut String, user: &GithubUserReport) {
    let _ = writeln!(
      out,
      "  {} {}",
      self.paint(Style::new().bold(), "GitHub"),
      self.paint(Style::new().cyan(), &user.username),
    );
    if let Some(profile) = &user.profile {
      if let Some(name) = &profile.name {
        let _ = writeln!(out, "    name: {name}");
      }
      if let Some(location) = &profile.location {
        let _ = writeln!(out, "    location: {location}");
      }
      if let Some(bio) = &profile.bio {
        let _ = writeln!(out, "    bio: {bio}");
      }
      if let Some(blog) = &profile.blog {
        let _ = writeln!(out, "    blog: {blog}");
      }
      if let Some(twitter) = &profile.twitter_username {
        let _ = writeln!(out, "    x/twitter: @{twitter}");
      }
    }
    let repos = &user.repositories;
    let _ = writeln!(
      out,
      "    repos: {} public, {} sources, {} forks, {} archived, {} mirrors, {} templates",
      repos.total_public,
      repos.sources,
      repos.forks,
      repos.archived,
      repos.mirrors,
      repos.templates,
    );
    let _ = writeln!(out, "    gists: {}", user.gists);
    if !user.organizations.is_empty() {
      let orgs = join_map(&user.organizations, ", ", |org| org.login.clone());
      let _ = writeln!(out, "    organizations: {orgs}");
    }
    if !user.social_accounts.is_empty() {
      let accounts = join_map(&user.social_accounts, ", ", |account| {
        format!("{} {}", account.provider, account.url)
      });
      let _ = writeln!(out, "    social: {accounts}");
    }
    if !user.friends.is_empty() {
      let friends = join_map(&user.friends, ", ", |friend| {
        friend.name.as_ref().map_or_else(
          || friend.login.clone(),
          |name| {
            if name == &friend.login {
              name.clone()
            } else {
              format!("{name} ({})", friend.login)
            }
          },
        )
      });
      let _ = writeln!(out, "    friends: {friends}");
    }
    if !user.similar_users.is_empty() {
      let similar = join_map(&user.similar_users, ", ", |similar| {
        similar.name.as_ref().map_or_else(
          || similar.login.clone(),
          |name| format!("{name} ({})", similar.login),
        )
      });
      let _ = writeln!(out, "    similar: {similar}");
    }
    if !user.commit_emails.is_empty() {
      let emails = join_map(&user.commit_emails, ", ", |email| {
        email.name.as_ref().map_or_else(
          || format!("{} ({})", email.email, email.count),
          |name| format!("{name} <{}> ({})", email.email, email.count),
        )
      });
      let _ = writeln!(out, "    commit emails: {emails}");
    }
    if !user.commit_names.is_empty() {
      let names = join_map(&user.commit_names, ", ", |name| {
        format!("{} ({})", name.name, name.count)
      });
      let _ = writeln!(out, "    commit names: {names}");
    }
    if !user.errors.is_empty() {
      let errors = join_map(&user.errors, "; ", |error| {
        format!("{}: {}", error.stage, error.message)
      });
      let _ = writeln!(
        out,
        "    {} {errors}",
        self.paint(Style::new().red(), "errors:"),
      );
    }
  }

  fn emit(&mut self, line: &str) -> io::Result<()> {
    match self.bar.clone() {
      Some(bar) => bar.suspend(|| writeln!(self.sink, "{line}")),
      None => writeln!(self.sink, "{line}"),
    }
  }
}

fn join_map<T>(items: &[T], sep: &str, f: impl Fn(&T) -> String) -> String {
  items.iter().map(f).collect::<Vec<_>>().join(sep)
}

const fn verdict_glyph(verdict: Verdict) -> &'static str {
  match verdict {
    Verdict::Found => "✓",
    Verdict::NotFound => "✗",
    Verdict::Uncertain => "?",
    Verdict::Blocked => "■",
    Verdict::RateLimited => "~",
    Verdict::Captcha => "▦",
    Verdict::LoginRequired => "⚿",
    Verdict::InvalidUsername => "!",
    Verdict::Skipped => "·",
  }
}

const fn verdict_style(verdict: Verdict) -> Style {
  let base = Style::new();
  match verdict {
    Verdict::Found => base.green().bold(),
    Verdict::Uncertain | Verdict::RateLimited => base.yellow(),
    Verdict::Blocked
    | Verdict::Captcha
    | Verdict::LoginRequired
    | Verdict::InvalidUsername => base.red(),
    Verdict::NotFound | Verdict::Skipped => base.dim(),
  }
}

fn format_elapsed(ms: u64) -> String {
  if ms < 1000 {
    format!("{ms}ms")
  } else if ms < 60_000 {
    format!("{}.{}s", ms / 1000, (ms % 1000) / 100)
  } else {
    let secs = ms / 1000;
    format!("{}m{:02}s", secs / 60, secs % 60)
  }
}

struct JsonWriter {
  sink: Sink,
}

impl OutputWriter for JsonWriter {
  fn on_event(&mut self, _event: &ScanEvent) -> io::Result<()> {
    Ok(())
  }

  fn finish(&mut self, report: &ScanReport) -> io::Result<()> {
    write_json_report(&mut self.sink, report)
  }
}

struct NdjsonWriter {
  sink: Sink,
}

fn write_json_report<T: serde::Serialize>(
  mut sink: impl Write,
  report: &T,
) -> io::Result<()> {
  let json = serde_json::to_string_pretty(report)
    .map_err(|e| io::Error::other(e.to_string()))?;
  writeln!(sink, "{json}")
}

fn write_ndjson_github_report(
  mut sink: Sink,
  report: &GithubBatchReport,
) -> io::Result<()> {
  for user in &report.users {
    let line = serde_json::to_string(user)
      .map_err(|e| io::Error::other(e.to_string()))?;
    writeln!(sink, "{line}")?;
  }
  sink.flush()
}

fn write_csv_github_report(
  mut sink: Sink,
  report: &GithubBatchReport,
) -> io::Result<()> {
  writeln!(
    sink,
    "username,profile_name,profile_url,total_public_repos,source_repos,\
     forks,gists,ssh_keys,friends,similar_users,commit_emails,commit_names,errors"
  )?;
  for user in &report.users {
    let profile_name = user
      .profile
      .as_ref()
      .and_then(|profile| profile.name.clone())
      .unwrap_or_default();
    let profile_url = user
      .profile
      .as_ref()
      .and_then(|profile| profile.html_url.clone())
      .unwrap_or_default();
    let fields = [
      user.username.clone(),
      profile_name,
      profile_url,
      user.repositories.total_public.to_string(),
      user.repositories.sources.to_string(),
      user.repositories.forks.to_string(),
      user.gists.to_string(),
      user.ssh_keys.len().to_string(),
      user.friends.len().to_string(),
      user.similar_users.len().to_string(),
      user.commit_emails.len().to_string(),
      user.commit_names.len().to_string(),
      user.errors.len().to_string(),
    ];
    writeln!(
      sink,
      "{}",
      fields
        .iter()
        .map(|field| csv_escape(field))
        .collect::<Vec<_>>()
        .join(",")
    )?;
  }
  sink.flush()
}

impl OutputWriter for NdjsonWriter {
  fn on_event(&mut self, event: &ScanEvent) -> io::Result<()> {
    let line = serde_json::to_string(event)
      .map_err(|e| io::Error::other(e.to_string()))?;
    writeln!(self.sink, "{line}")
  }

  fn finish(&mut self, _report: &ScanReport) -> io::Result<()> {
    self.sink.flush()
  }
}

struct CsvWriter {
  sink: Sink,
  scan_id: String,
}

impl OutputWriter for CsvWriter {
  fn on_event(&mut self, event: &ScanEvent) -> io::Result<()> {
    match event {
      ScanEvent::ScanStarted { scan_id, .. } => {
        self.scan_id = scan_id.to_string();
        writeln!(
          self.sink,
          "scan_id,username,site_id,site_name,verdict,\
           profile_url,status,final_url,elapsed_ms,error_kind"
        )
      }
      ScanEvent::Result { result } => self.write_row(result),
      _ => Ok(()),
    }
  }

  fn finish(&mut self, _report: &ScanReport) -> io::Result<()> {
    self.sink.flush()
  }
}

impl CsvWriter {
  fn write_row(&mut self, r: &SiteResult) -> io::Result<()> {
    let status = r.probe.status.map_or_else(String::new, |s| s.to_string());
    let final_url = r.probe.final_url.clone().unwrap_or_default();
    let error_kind = r
      .error
      .as_ref()
      .map_or_else(String::new, |e| format!("{:?}", e.kind));
    let fields = [
      self.scan_id.clone(),
      r.username.clone(),
      r.site_id.clone(),
      r.site_name.clone(),
      r.verdict.as_str().to_string(),
      r.profile_url.clone().unwrap_or_default(),
      status,
      final_url,
      r.probe.elapsed_ms.to_string(),
      error_kind,
    ];
    writeln!(
      self.sink,
      "{}",
      fields
        .iter()
        .map(|f| csv_escape(f))
        .collect::<Vec<_>>()
        .join(",")
    )
  }
}

fn csv_escape(field: &str) -> Cow<'_, str> {
  if field.contains([',', '"', '\n', '\r']) {
    Cow::Owned(format!("\"{}\"", field.replace('"', "\"\"")))
  } else {
    Cow::Borrowed(field)
  }
}

fn should_print(result: &SiteResult, print: PrintArg) -> bool {
  match print {
    PrintArg::Found => result.verdict == Verdict::Found,
    PrintArg::All => true,
    PrintArg::Uncertain => {
      matches!(result.verdict, Verdict::Found | Verdict::Uncertain)
    }
    PrintArg::Errors => {
      result.verdict == Verdict::Found || result.error.is_some()
    }
  }
}

fn truncate(value: &str, max: usize) -> String {
  if value.chars().count() <= max {
    value.to_string()
  } else {
    let mut s: String = value.chars().take(max.saturating_sub(1)).collect();
    s.push('…');
    s
  }
}
