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
mycroft check beowolx

# Check several at once
mycroft check alice bob

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

Run `mycroft check --help` for the full list of flags.

## License

MIT. See [`LICENSE`](LICENSE).
