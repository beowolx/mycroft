mod args;
mod config_file;
mod exit;
mod logging;
mod output;
mod progress;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{CommandFactory, Parser};

use mycroft_core::CancellationToken;
use mycroft_core::event::EventSender;
use mycroft_core::github::{GithubError, GithubOptions, enrich_github};
use mycroft_core::net::FetchSettings;
use mycroft_core::result::{ScanReport, ScanSummary};
use mycroft_core::scan::{ScanInput, SiteSelection};
use mycroft_core::{RuntimeConfig, ScanError, SubjectKind, scan_with_events};
use mycroft_manifest::Manifest;

use crate::args::{
  CheckArgs, Cli, Commands, FailOnArg, GithubArgs, ManifestCmd, PrintArg,
  SitesCmd,
};
use crate::config_file::ManifestSource;
use crate::exit::Exit;
use crate::output::{
  HumanOptions, OutputWriter, make_writer, write_github_report,
};
use crate::progress::Progress;

#[tokio::main]
async fn main() -> ExitCode {
  raise_fd_limit();
  let command_args = inject_default_subcommand(std::env::args().collect());
  let cli = Cli::try_parse_from(command_args).unwrap_or_else(|e| e.exit());

  let exit = match cli.command {
    Commands::Check(args) => run_check(args, SubjectKind::Username).await,
    Commands::Email(args) => run_check(args, SubjectKind::Email).await,
    Commands::Github(args) => run_github(args).await,
    Commands::Sites { cmd } => run_sites(cmd).await,
    Commands::Manifest { cmd } => run_manifest(cmd),
    Commands::Completions { shell } => {
      let mut cmd = Cli::command();
      clap_complete::generate(
        shell,
        &mut cmd,
        "mycroft",
        &mut std::io::stdout(),
      );
      Exit::Ok
    }
  };
  exit.into()
}

fn raise_fd_limit() {
  let _ = rlimit::increase_nofile_limit(65_536);
}

fn inject_default_subcommand(mut argv: Vec<String>) -> Vec<String> {
  const SUBCOMMANDS: &[&str] = &[
    "check",
    "email",
    "github",
    "sites",
    "manifest",
    "completions",
    "help",
  ];
  if argv.len() >= 2 {
    let first = argv[1].as_str();
    let is_help_or_version =
      matches!(first, "-h" | "--help" | "-V" | "--version");
    if !is_help_or_version && !SUBCOMMANDS.contains(&first) {
      argv.insert(1, "check".to_string());
    }
  }
  argv
}

async fn run_check(args: CheckArgs, kind: SubjectKind) -> Exit {
  let file = match config_file::load() {
    Ok(file) => file,
    Err(error) => {
      eprintln!("error: {error}");
      return Exit::Usage;
    }
  };
  logging::init(args.output.verbose, args.output.quiet);

  let source = config_file::resolve_manifest_source(&args, &file);
  let manifest = match load_manifest(&source, &args).await {
    Ok(manifest) => manifest,
    Err(exit) => return exit,
  };

  let settings =
    config_file::resolve_settings(&args, &file, &manifest.defaults);

  if settings.runtime.proxy.is_none() && settings.proxy_required {
    eprintln!("error: --proxy-required set but no proxy was configured");
    return Exit::NetworkSetup;
  }

  let usernames = match gather_subjects(&args, kind) {
    Ok(names) if !names.is_empty() => names,
    Ok(_) => {
      eprintln!("error: no {} provided", subject_noun(kind));
      return Exit::Usage;
    }
    Err(exit) => return exit,
  };

  let input = ScanInput {
    usernames,
    subject_kind: kind,
    site_selection: SiteSelection {
      include_sites: args.input.sites.clone(),
      exclude_sites: args.input.exclude_sites.clone(),
      include_tags: args.input.tags.clone(),
      exclude_tags: args.input.exclude_tags.clone(),
    },
    include_nsfw: settings.include_nsfw,
    include_email_sending: args.input.allow_email_sending,
  };

  if input.include_email_sending {
    eprintln!(
      "warning: --allow-email-sending enabled; sites that probe account-recovery endpoints may send a real email or SMS to the address if it is registered"
    );
  }

  let sink = match open_sink(args.output.output_path.as_ref()) {
    Ok(sink) => sink,
    Err(exit) => return exit,
  };
  let progress = Progress::new(settings.progress);
  let color = args.output.output_path.is_none() && console::colors_enabled();
  let mut writer = make_writer(
    settings.format,
    sink,
    HumanOptions {
      print: settings.print,
      verbose: args.output.verbose,
      quiet: args.output.quiet,
      color,
      bar: progress.bar(),
    },
  );

  let report = match execute_scan(
    input,
    manifest,
    settings.runtime,
    writer.as_mut(),
    &progress,
  )
  .await
  {
    Ok(report) => report,
    Err(exit) => return exit,
  };

  if let Err(e) = writer.finish(&report) {
    eprintln!("error: failed to write output: {e}");
    return Exit::Io;
  }

  compute_exit(
    &report.summary,
    args.policy.fail_on,
    args.policy.fail_on_partial,
  )
}

async fn run_github(args: GithubArgs) -> Exit {
  let file = match config_file::load() {
    Ok(file) => file,
    Err(error) => {
      eprintln!("error: {error}");
      return Exit::Usage;
    }
  };
  logging::init(args.output.verbose, args.output.quiet);

  let settings = config_file::resolve_github_settings(&args, &file);
  if settings.runtime.proxy.is_none() && settings.proxy_required {
    eprintln!("error: --proxy-required set but no proxy was configured");
    return Exit::NetworkSetup;
  }

  let usernames = match gather_github_subjects(&args) {
    Ok(names) if !names.is_empty() => names,
    Ok(_) => {
      eprintln!("error: no usernames provided");
      return Exit::Usage;
    }
    Err(exit) => return exit,
  };

  let sink = match open_sink(args.output.output_path.as_ref()) {
    Ok(sink) => sink,
    Err(exit) => return exit,
  };
  let progress = Progress::new(settings.progress);
  let color = args.output.output_path.is_none() && console::colors_enabled();
  let cancel = CancellationToken::new();
  spawn_interrupt_handler(cancel.clone());

  let report = match enrich_github(
    &usernames,
    &settings.runtime,
    GithubOptions::default(),
    cancel,
  )
  .await
  {
    Ok(report) => report,
    Err(error) => {
      eprintln!("error: GitHub enrichment failed: {error}");
      return github_error_exit(&error);
    }
  };

  let human = HumanOptions {
    print: PrintArg::Found,
    verbose: args.output.verbose,
    quiet: args.output.quiet,
    color,
    bar: progress.bar(),
  };
  if let Err(error) = write_github_report(settings.format, sink, human, &report)
  {
    eprintln!("error: failed to write output: {error}");
    return Exit::Io;
  }

  Exit::Ok
}

const fn github_error_exit(error: &GithubError) -> Exit {
  match error {
    GithubError::InvalidBaseUrl(_) => Exit::Usage,
    GithubError::NetworkConfig(_) => Exit::NetworkSetup,
    GithubError::Interrupted => Exit::Interrupted,
  }
}

async fn execute_scan(
  input: ScanInput,
  manifest: Manifest,
  runtime: RuntimeConfig,
  writer: &mut dyn OutputWriter,
  progress: &Progress,
) -> Result<ScanReport, Exit> {
  let (events, mut receiver) = EventSender::channel();
  let cancel = CancellationToken::new();
  spawn_interrupt_handler(cancel.clone());

  let scan =
    tokio::spawn(scan_with_events(input, manifest, runtime, events, cancel));

  while let Some(event) = receiver.recv().await {
    progress.on_event(&event);
    if let Err(e) = writer.on_event(&event) {
      eprintln!("warning: failed to write output: {e}");
    }
  }

  match scan.await {
    Ok(Ok(report)) => Ok(report),
    Ok(Err(error)) => Err(scan_error_exit(&error)),
    Err(_) => Err(Exit::Internal),
  }
}

fn scan_error_exit(error: &ScanError) -> Exit {
  match error {
    ScanError::NoUsernames | ScanError::NoSites => {
      eprintln!("error: {error}");
      Exit::Usage
    }
    ScanError::NetworkConfig(_) => {
      eprintln!("error: {error}");
      Exit::NetworkSetup
    }
    ScanError::Interrupted => Exit::Interrupted,
    ScanError::Internal(_) => {
      eprintln!("error: {error}");
      Exit::Internal
    }
  }
}

const fn compute_exit(
  summary: &ScanSummary,
  fail_on: Option<FailOnArg>,
  fail_on_partial: bool,
) -> Exit {
  if summary.interrupted {
    return Exit::Interrupted;
  }
  if let Some(fail_on) = fail_on {
    let triggered = match fail_on {
      FailOnArg::None => false,
      FailOnArg::Found => summary.found > 0,
      FailOnArg::Uncertain => summary.uncertain > 0,
      FailOnArg::NotFound => summary.not_found > 0,
    };
    if triggered {
      return Exit::Policy;
    }
  }
  if fail_on_partial
    && (summary.errors > 0 || summary.blocked > 0 || summary.rate_limited > 0)
  {
    return Exit::Partial;
  }
  Exit::Ok
}

const fn subject_noun(kind: SubjectKind) -> &'static str {
  match kind {
    SubjectKind::Username => "usernames",
    SubjectKind::Email => "email addresses",
  }
}

fn read_raw_subjects(
  explicit: &[String],
  usernames_file: Option<&PathBuf>,
) -> Result<Vec<String>, Exit> {
  let mut raw: Vec<String> = explicit.to_vec();
  if let Some(path) = usernames_file {
    let contents = std::fs::read_to_string(path).map_err(|e| {
      eprintln!("error: failed to read {}: {e}", path.display());
      Exit::Io
    })?;
    for line in contents.lines() {
      let line = line.trim();
      if !line.is_empty() && !line.starts_with('#') {
        raw.push(line.to_string());
      }
    }
  }
  Ok(raw)
}

fn gather_subjects(
  args: &CheckArgs,
  kind: SubjectKind,
) -> Result<Vec<mycroft_core::Username>, Exit> {
  let raw =
    read_raw_subjects(&args.usernames, args.input.usernames_file.as_ref())?;
  match kind {
    SubjectKind::Username => {
      gather_usernames(&raw, args.input.variant_placeholder)
    }
    SubjectKind::Email => gather_emails(&raw),
  }
}

fn gather_github_subjects(
  args: &GithubArgs,
) -> Result<Vec<mycroft_core::Username>, Exit> {
  let raw = read_raw_subjects(&args.usernames, args.usernames_file.as_ref())?;
  gather_usernames(&raw, args.variant_placeholder)
}

fn gather_usernames(
  raw: &[String],
  variant_placeholder: bool,
) -> Result<Vec<mycroft_core::Username>, Exit> {
  let mut usernames = Vec::new();
  for value in raw {
    match mycroft_core::username::expand_variants(value, variant_placeholder) {
      Ok(expanded) => usernames.extend(expanded),
      Err(e) => {
        eprintln!("error: invalid username '{value}': {e}");
        return Err(Exit::Usage);
      }
    }
  }
  Ok(usernames)
}

fn gather_emails(raw: &[String]) -> Result<Vec<mycroft_core::Username>, Exit> {
  let mut emails = Vec::new();
  for value in raw {
    let email = mycroft_core::Email::parse(value).map_err(|e| {
      eprintln!("error: invalid email '{value}': {e}");
      Exit::Usage
    })?;
    let subject = mycroft_core::Username::parse(email.as_str()).map_err(|e| {
      eprintln!("error: invalid email '{value}': {e}");
      Exit::Usage
    })?;
    emails.push(subject);
  }
  Ok(emails)
}

fn open_sink(path: Option<&PathBuf>) -> Result<output::Sink, Exit> {
  path.map_or_else(
    || Ok(Box::new(std::io::stdout()) as output::Sink),
    |path| {
      std::fs::File::create(path)
        .map(|f| Box::new(f) as output::Sink)
        .map_err(|e| {
          eprintln!("error: cannot open {}: {e}", path.display());
          Exit::Io
        })
    },
  )
}

fn spawn_interrupt_handler(cancel: CancellationToken) {
  tokio::spawn(async move {
    if tokio::signal::ctrl_c().await.is_ok() {
      cancel.cancel();
    }
  });
}

async fn load_manifest(
  source: &ManifestSource,
  args: &CheckArgs,
) -> Result<Manifest, Exit> {
  let result = match source {
    ManifestSource::Bundled => mycroft_manifest::bundled_manifest(),
    ManifestSource::Path(path) => mycroft_manifest::load_manifest_path(path),
    ManifestSource::Url(url) => {
      let settings = FetchSettings {
        proxy: if args.network.tor {
          Some(mycroft_core::config::TOR_PROXY_URL.to_string())
        } else {
          args.network.proxy.clone()
        },
        allow_private: args.network.allow_private_targets,
      };
      let bytes = fetch_remote_manifest(url, &settings).await?;
      mycroft_manifest::parse_manifest_bytes(&bytes)
    }
  };
  result.map_err(|e| {
    eprintln!("error: failed to load manifest: {e}");
    Exit::Usage
  })
}

async fn fetch_remote_manifest(
  url: &str,
  settings: &FetchSettings,
) -> Result<Vec<u8>, Exit> {
  if !url.starts_with("https://") && !settings.allow_private {
    eprintln!("error: remote manifests must use HTTPS");
    return Err(Exit::Usage);
  }
  mycroft_core::net::fetch_bytes(url, settings)
    .await
    .map_err(|e| {
      eprintln!("error: failed to fetch manifest: {e}");
      Exit::NetworkSetup
    })
}

async fn run_sites(cmd: SitesCmd) -> Exit {
  match cmd {
    SitesCmd::List {
      manifest,
      include_nsfw,
    } => run_sites_list(manifest.as_deref(), include_nsfw).await,
    SitesCmd::Show { site, manifest } => {
      run_sites_show(&site, manifest.as_deref()).await
    }
  }
}

async fn run_sites_list(manifest: Option<&str>, include_nsfw: bool) -> Exit {
  let manifest = match load_manifest_opt(manifest).await {
    Ok(m) => m,
    Err(exit) => return exit,
  };
  let mut count = 0;
  for site in &manifest.sites {
    if site.nsfw && !include_nsfw {
      continue;
    }
    let tags = if site.tags.is_empty() {
      String::new()
    } else {
      format!(" [{}]", site.tags.join(", "))
    };
    let nsfw = if site.nsfw { " (nsfw)" } else { "" };
    println!("{:<28} {}{tags}{nsfw}", site.id, site.name);
    count += 1;
  }
  println!("\n{count} sites");
  Exit::Ok
}

async fn run_sites_show(site: &str, manifest: Option<&str>) -> Exit {
  let manifest = match load_manifest_opt(manifest).await {
    Ok(m) => m,
    Err(exit) => return exit,
  };
  let Some(found) = manifest
    .sites
    .iter()
    .find(|s| mycroft_core::scan::site_matches(s, site))
  else {
    eprintln!("error: site '{site}' not found");
    return Exit::Usage;
  };
  match serde_json::to_string_pretty(found) {
    Ok(json) => {
      println!("{json}");
      Exit::Ok
    }
    Err(e) => {
      eprintln!("error: {e}");
      Exit::Internal
    }
  }
}

async fn load_manifest_opt(source: Option<&str>) -> Result<Manifest, Exit> {
  let result = match source {
    None => mycroft_manifest::bundled_manifest(),
    Some(s) if s.starts_with("http://") || s.starts_with("https://") => {
      let bytes = fetch_remote_manifest(s, &FetchSettings::default()).await?;
      mycroft_manifest::parse_manifest_bytes(&bytes)
    }
    Some(path) => {
      mycroft_manifest::load_manifest_path(std::path::Path::new(path))
    }
  };
  result.map_err(|e| {
    eprintln!("error: failed to load manifest: {e}");
    Exit::Usage
  })
}

fn run_manifest(cmd: ManifestCmd) -> Exit {
  match cmd {
    ManifestCmd::Validate { path } => run_manifest_validate(path.as_deref()),
    ManifestCmd::ImportCatalog { data_json } => run_manifest_import(&data_json),
  }
}

fn run_manifest_validate(path: Option<&Path>) -> Exit {
  let result = path.map_or_else(mycroft_manifest::bundled_manifest, |path| {
    mycroft_manifest::load_manifest_path(path)
  });
  match result {
    Ok(manifest) => {
      println!("OK: {} sites validated", manifest.sites.len());
      Exit::Ok
    }
    Err(e) => {
      eprintln!("error: {e}");
      Exit::Usage
    }
  }
}

fn run_manifest_import(data_json: &Path) -> Exit {
  let raw = match std::fs::read_to_string(data_json) {
    Ok(s) => s,
    Err(e) => {
      eprintln!("error: cannot read {}: {e}", data_json.display());
      return Exit::Io;
    }
  };
  let value: serde_json::Value = match serde_json::from_str(&raw) {
    Ok(v) => v,
    Err(e) => {
      eprintln!("error: invalid JSON: {e}");
      return Exit::Usage;
    }
  };
  let manifest = match mycroft_manifest::import_catalog::import_catalog(
    &value,
    "mycroft-imported",
    None,
  ) {
    Ok(manifest) => manifest,
    Err(e) => {
      eprintln!("error: import failed: {e}");
      return Exit::Usage;
    }
  };
  match serde_json::to_string_pretty(&manifest) {
    Ok(json) => {
      println!("{json}");
      Exit::Ok
    }
    Err(e) => {
      eprintln!("error: {e}");
      Exit::Internal
    }
  }
}

#[cfg(test)]
mod tests {
  use mycroft_core::result::ScanSummary;

  use crate::args::FailOnArg;
  use crate::compute_exit;
  use crate::exit::Exit;

  #[test]
  fn ok_when_nothing_triggers() {
    assert_eq!(compute_exit(&ScanSummary::default(), None, false), Exit::Ok);
  }

  #[test]
  fn interrupted_beats_every_policy() {
    let mut s = ScanSummary {
      found: 3,
      errors: 2,
      ..ScanSummary::default()
    };
    s.interrupted = true;
    assert_eq!(
      compute_exit(&s, Some(FailOnArg::Found), true),
      Exit::Interrupted
    );
  }

  #[test]
  fn fail_on_found_triggers_policy() {
    let s = ScanSummary {
      found: 1,
      ..ScanSummary::default()
    };
    assert_eq!(
      compute_exit(&s, Some(FailOnArg::Found), false),
      Exit::Policy
    );
  }

  #[test]
  fn policy_takes_precedence_over_partial() {
    let s = ScanSummary {
      found: 1,
      errors: 1,
      ..ScanSummary::default()
    };
    assert_eq!(compute_exit(&s, Some(FailOnArg::Found), true), Exit::Policy);
  }

  #[test]
  fn fail_on_partial_triggers_on_recoverable_failures() {
    let s = ScanSummary {
      blocked: 1,
      ..ScanSummary::default()
    };
    assert_eq!(compute_exit(&s, None, true), Exit::Partial);
    assert_eq!(compute_exit(&s, None, false), Exit::Ok);
  }
}
