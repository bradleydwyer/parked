use crate::types::WhoisInfo;
use std::collections::HashMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{Duration, timeout};

const WHOIS_TIMEOUT: Duration = Duration::from_secs(5);

fn whois_servers() -> HashMap<&'static str, &'static str> {
    let mut m = HashMap::new();
    m.insert("com", "whois.verisign-grs.com");
    m.insert("net", "whois.verisign-grs.com");
    m.insert("org", "whois.pir.org");
    m.insert("io", "whois.nic.io");
    m.insert("dev", "whois.nic.google");
    m.insert("app", "whois.nic.google");
    m.insert("xyz", "whois.nic.xyz");
    m.insert("info", "whois.afilias.net");
    m.insert("me", "whois.nic.me");
    m.insert("co", "whois.nic.co");
    m.insert("cc", "ccwhois.verisign-grs.com");
    m.insert("tv", "tvwhois.verisign-grs.com");
    m.insert("us", "whois.nic.us");
    m.insert("biz", "whois.nic.biz");
    m.insert("mobi", "whois.nic.mobi");
    m.insert("name", "whois.nic.name");
    m.insert("uk", "whois.nic.uk");
    m.insert("de", "whois.denic.de");
    m.insert("fr", "whois.nic.fr");
    m.insert("au", "whois.auda.org.au");
    m.insert("ca", "whois.cira.ca");
    m.insert("nl", "whois.sidn.nl");
    m.insert("eu", "whois.eu");
    m.insert("ru", "whois.tcinet.ru");
    m.insert("ch", "whois.nic.ch");
    m.insert("jp", "whois.jprs.jp");
    m.insert("kr", "whois.kr");
    m.insert("cn", "whois.cnnic.cn");
    m.insert("in", "whois.registry.in");
    m.insert("br", "whois.registro.br");
    m.insert("it", "whois.nic.it");
    m.insert("se", "whois.iis.se");
    m.insert("no", "whois.norid.no");
    m.insert("fi", "whois.fi");
    m.insert("be", "whois.dns.be");
    m.insert("at", "whois.nic.at");
    m.insert("pl", "whois.dns.pl");
    m.insert("cz", "whois.nic.cz");
    m
}

fn extract_tld(domain: &str) -> Option<&str> {
    domain.rsplit('.').next()
}

pub async fn lookup(domain: &str) -> Result<WhoisInfo, String> {
    let tld = extract_tld(domain).ok_or_else(|| "Invalid domain: no TLD".to_string())?;

    let servers = whois_servers();
    let server = servers
        .get(tld)
        .ok_or_else(|| format!("No WHOIS server known for TLD: .{tld}"))?;

    let addr = format!("{server}:43");

    let raw_response = timeout(WHOIS_TIMEOUT, async {
        let mut stream = TcpStream::connect(&addr)
            .await
            .map_err(|e| format!("WHOIS connect failed: {e}"))?;

        stream
            .write_all(format!("{domain}\r\n").as_bytes())
            .await
            .map_err(|e| format!("WHOIS write failed: {e}"))?;

        let mut buf = Vec::new();
        stream
            .read_to_end(&mut buf)
            .await
            .map_err(|e| format!("WHOIS read failed: {e}"))?;

        Ok::<String, String>(String::from_utf8_lossy(&buf).to_string())
    })
    .await
    .map_err(|_| "WHOIS lookup timed out".to_string())??;

    let lower = raw_response.to_lowercase();

    // Check for "not found" patterns
    let not_found_patterns = [
        "no match",
        "not found",
        "no data found",
        "no entries found",
        "nothing found",
        "status: free",
        "status: available",
        "domain not found",
        "no object found",
        "object does not exist",
    ];

    let is_not_found = not_found_patterns.iter().any(|p| lower.contains(p));

    // Extract registrar
    let registrar = raw_response
        .lines()
        .find(|line| {
            let l = line.to_lowercase();
            l.starts_with("registrar:") || l.starts_with("   registrar:")
        })
        .and_then(|line| line.split_once(':').map(|(_, v)| v.trim().to_string()));

    // Extract creation date
    let creation_date = raw_response
        .lines()
        .find(|line| {
            let l = line.to_lowercase();
            l.contains("creation date") || l.contains("created") || l.contains("registration date")
        })
        .and_then(|line| line.split_once(':').map(|(_, v)| v.trim().to_string()));

    let found = !is_not_found && (registrar.is_some() || creation_date.is_some());

    // Truncate raw response for storage
    let truncated = if raw_response.len() > 500 {
        format!("{}...", &raw_response[..500])
    } else {
        raw_response
    };

    Ok(WhoisInfo {
        raw_response: truncated,
        registrar,
        creation_date,
        found,
    })
}
