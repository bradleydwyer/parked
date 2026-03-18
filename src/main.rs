use parked::checker;

const COMMON_TLDS: &[&str] = &[
    // Generic
    "com", "net", "org", "info", "biz",
    // Tech / dev
    "io", "dev", "app", "sh", "ai", "co", "run", "build", "codes", "tools", "tech", "cloud",
    "pro", "engineer", "software",
    // Short / brandable
    "xyz", "me", "cc", "tv", "gg", "lol", "wtf", "fyi", "one", "plus",
    // Descriptive
    "land", "page", "site", "space", "zone", "works", "world", "live", "team",
    // Country codes
    "us", "uk", "de", "fr", "nl", "se", "no", "fi", "ch", "at", "be", "dk", "ie", "nz", "au",
    "ca", "mx", "br", "ar", "jp", "kr", "tw", "hk", "sg", "ph", "th", "vn", "id", "my", "za",
    "in", "it", "is", "to", "fm", "ly", "so",
];

fn expand_all_tlds(names: &[String]) -> Vec<String> {
    names
        .iter()
        .flat_map(|name| {
            // Strip any existing TLD if present (e.g. "equip.com" -> "equip")
            let base = name.split('.').next().unwrap_or(name);
            COMMON_TLDS.iter().map(move |tld| format!("{base}.{tld}"))
        })
        .collect()
}
use parked::mcp::ParkedMcp;
use rmcp::{ServiceExt, transport::stdio};

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "parked",
    about = "Tiered domain availability checker (DNS → WHOIS → RDAP)",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    /// Domain names to check
    domains: Vec<String>,

    /// Output results as JSON
    #[arg(short, long)]
    json: bool,

    /// Show tier-by-tier details
    #[arg(short, long)]
    verbose: bool,

    /// Check a name across all common TLDs (pass name without TLD)
    #[arg(long)]
    all_tlds: bool,
}

#[derive(Subcommand)]
enum Command {
    /// Start MCP server (stdio transport)
    Mcp,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    if let Some(Command::Mcp) = cli.command {
        let server = ParkedMcp::new();
        let service = server.serve(stdio()).await?;
        service.waiting().await?;
        return Ok(());
    }

    if cli.domains.is_empty() {
        eprintln!("Usage: parked [OPTIONS] <DOMAINS>...");
        eprintln!("       parked mcp");
        eprintln!();
        eprintln!("Run 'parked --help' for more information.");
        std::process::exit(1);
    }

    let domains = if cli.all_tlds {
        expand_all_tlds(&cli.domains)
    } else {
        cli.domains.clone()
    };

    let results = checker::check_domains(&domains).await;

    if cli.json {
        println!("{}", serde_json::to_string_pretty(&results)?);
    } else {
        for result in &results {
            if cli.verbose {
                println!(
                    "{:<30} {:<12} ({}, {}ms)",
                    result.domain, result.available, result.determined_by, result.elapsed_ms
                );
                if let Some(ref dns) = result.details.dns {
                    println!(
                        "  DNS: has_records={}, types={:?}",
                        dns.has_records, dns.record_types
                    );
                }
                if let Some(ref whois) = result.details.whois {
                    println!(
                        "  WHOIS: found={}, registrar={:?}",
                        whois.found, whois.registrar
                    );
                }
                if let Some(ref rdap) = result.details.rdap {
                    println!(
                        "  RDAP: status={}, found={}, registrar={:?}",
                        rdap.status_code, rdap.found, rdap.registrar
                    );
                }
            } else {
                println!(
                    "{:<30} {:<12} ({}, {}ms)",
                    result.domain, result.available, result.determined_by, result.elapsed_ms
                );
            }
        }
    }

    Ok(())
}
