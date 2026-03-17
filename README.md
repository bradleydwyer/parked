# domain-check

Check if a domain name is registered. Uses tiered lookups: DNS first (fast), then WHOIS, then RDAP.

Also runs as an MCP server.

## Install

```bash
brew install bradleydwyer/tap/domain-check
```

Or from source (Rust 1.85+):

```bash
cargo install --git https://github.com/bradleydwyer/domain-check
```

## Usage

### Check a domain

```
$ domain-check example.com
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

Shows tier-by-tier details: DNS record types, WHOIS registrar, RDAP status.

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

```bash
domain-check mcp
```

Two tools over stdio:

| Tool | Description |
|------|-------------|
| `check_domain` | Check a single domain |
| `check_domains` | Check up to 50 domains concurrently |

Claude Code config:

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

## How it works

Each domain goes through up to three tiers:

1. **DNS** - Queries NS, A, and AAAA records. If any exist, the domain is registered. This catches most cases in under 50ms.
2. **WHOIS** - Connects to the TLD's WHOIS server (port 43). Parses the response for registrar info and "not found" patterns.
3. **RDAP** - Fetches the IANA bootstrap file to find the right server, then queries the API. A 404 means available.

If a tier confirms registration, later tiers are skipped. If all tiers are inconclusive, the result is `unknown`.

Built-in WHOIS server mappings for 30+ TLDs, plus IANA bootstrap for RDAP.

## License

MIT
