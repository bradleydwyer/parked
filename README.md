# domain-check

Tiered domain availability checker (DNS → WHOIS → RDAP) with CLI and MCP server.

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

## About

`domain-check` determines whether a domain name is registered by querying progressively authoritative sources. It starts with a fast DNS lookup, falls back to WHOIS, and finally checks RDAP for a definitive answer. This tiered approach keeps most lookups fast while still handling edge cases.

It works as both a standalone CLI tool and as an [MCP](https://modelcontextprotocol.io/) server, so AI assistants like Claude can check domain availability directly.

## Features

- **Tiered lookups** — DNS first (fast), then WHOIS, then RDAP. Stops as soon as registration is confirmed.
- **Concurrent batch checks** — Look up multiple domains in parallel with a configurable concurrency limit.
- **MCP server** — Expose `check_domain` and `check_domains` as tools over stdio transport.
- **JSON output** — Machine-readable results with per-tier details and timing.
- **Broad TLD support** — Built-in WHOIS server mappings for 30+ TLDs, plus IANA bootstrap for RDAP.

## Installation

### Homebrew (macOS)

```bash
brew install bradleydwyer/tap/domain-check
```

### From source (requires Rust 1.85+)

```bash
git clone https://github.com/bradleydwyer/domain-check.git
cd domain-check
cargo build --release
```

The binary will be at `target/release/domain-check`.

### Requirements

- Rust 1.85+ (edition 2024)

## Usage

### Check a single domain

```bash
domain-check example.com
```

```
example.com                    REGISTERED   (dns, 45ms)
```

### Check multiple domains

```bash
domain-check example.com xyznotregistered123.com google.com
```

### Verbose output

```bash
domain-check -v example.com
```

Shows tier-by-tier details including DNS record types, WHOIS registrar, and RDAP status.

### JSON output

```bash
domain-check -j example.com
```

```json
[
  {
    "domain": "example.com",
    "available": "registered",
    "determined_by": "dns",
    "details": {
      "dns": {
        "has_records": true,
        "record_types": ["NS"]
      }
    },
    "elapsed_ms": 45
  }
]
```

### MCP server

Start the MCP server over stdio:

```bash
domain-check mcp
```

#### Claude Code configuration

Add to your MCP settings:

```json
{
  "mcpServers": {
    "domain-check": {
      "command": "/path/to/domain-check",
      "args": ["mcp"]
    }
  }
}
```

The server exposes two tools:

| Tool | Description |
|------|-------------|
| `check_domain` | Check a single domain for availability |
| `check_domains` | Check up to 50 domains concurrently |

## How It Works

Each domain is checked through up to three tiers:

1. **DNS** — Queries NS, A, and AAAA records using [hickory-resolver](https://github.com/hickory-dns/hickory-dns). If any records exist, the domain is registered.
2. **WHOIS** — Connects to the appropriate WHOIS server (port 43) for the domain's TLD. Parses the response for registrar info and "not found" patterns.
3. **RDAP** — Fetches the IANA RDAP bootstrap file to find the correct server, then queries the RDAP API. A 404 means the domain is available.

If a tier confirms registration, later tiers are skipped. If all tiers fail or are inconclusive, the result is `unknown`.

## Contributing

Contributions are welcome! Please open an issue or pull request.

### Development setup

```bash
git clone https://github.com/bradleydwyer/domain-check.git
cd domain-check
cargo build
```

### Running

```bash
cargo run -- example.com
cargo run -- -j -v example.com google.com
cargo run -- mcp
```

## License

domain-check is licensed under the MIT license. See the [`LICENSE`](LICENSE) file for details.
