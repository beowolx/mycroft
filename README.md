# mycroft

A fast OSINT tool that checks whether a username exists across a catalog of
public websites.

## Install

```bash
cargo install --path crates/mycroft-cli --locked
```

This installs the `mycroft` binary into `~/.cargo/bin`.

## Commands

```bash
# Check a username
mycroft check torvalds

# Check several at once
mycroft check alice bob

# Check whether an email has an account on email-aware sites
mycroft email alice@example.com

# Several emails, JSON output
mycroft email alice@example.com bob@example.com --format json

# Also probe account-recovery endpoints (these may email/SMS the address
# if it is registered); off by default
mycroft email alice@example.com --allow-email-sending

# Enrich a GitHub account
mycroft github torvalds

# Several accounts at once, JSON output
mycroft github alice bob --format json --output github.json

# Only certain sites
mycroft check alice --site github --site gitlab

# Save results as JSON
mycroft check alice --format json --output results.json

# Route through Tor
mycroft check alice --tor --proxy-required

# Browse the site catalog
mycroft sites list
mycroft sites show github
```

Run `mycroft <command> --help` (e.g. `mycroft github --help`) for the full
list of flags.

## License

MIT. See [`LICENSE`](LICENSE).
