---
name: parked
description: "Check if a domain name is registered or available. Uses tiered lookups (DNS, WHOIS, RDAP) for fast, reliable results. Use when a user wants to check domain availability, find unregistered domains, or verify registration status."
allowed-tools:
  - Bash(parked:*)
user-invocable: true
argument-hint: "<domain or space-separated domains>"
metadata:
  author: bradleydwyer
  version: "2.2.2"
  status: experimental
---

# parked -- Domain Availability Lookup

Checks whether domain names are registered using tiered lookups: DNS first (fast), then WHOIS, then RDAP. Each tier adds certainty at the cost of latency. Most lookups resolve at the DNS tier in under 100ms.

## When to Use This Skill

- User asks if a domain is available or taken
- User wants to check registration status of one or more domains
- User is brainstorming project names and wants to filter by domain availability

## Usage

Always use `-j` for JSON output so results can be parsed reliably.

```bash
# Single domain
parked -j example.com

# Multiple domains
parked -j foo.com bar.dev baz.io
```

## JSON Output

Each result contains:

- `domain`: the queried domain
- `available`: one of `registered`, `available`, `unknown`
- `determined_by`: which tier resolved it (`dns`, `whois`, `rdap`)
- `details`: per-tier breakdown of what each lookup found
- `elapsed_ms`: total lookup time

## Workflow

1. Run `parked -j` with the requested domain(s).
2. Parse the JSON output.
3. Report results clearly: which domains are available, which are registered, and which came back unknown.
4. If the user is exploring options, suggest checking variations (alternate TLDs, prefixes, etc.) and offer to run those checks.

## Verbose Mode

If debugging or the user wants tier-by-tier details in human-readable form:

```bash
parked -v example.com
```

This is for diagnostics only. Always prefer `-j` for normal operation.
