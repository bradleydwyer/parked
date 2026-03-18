use crate::types::RdapInfo;
use reqwest::Client;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::OnceLock;
use tokio::sync::Mutex;

static RDAP_CACHE: OnceLock<Mutex<Option<HashMap<String, String>>>> = OnceLock::new();

#[derive(Deserialize)]
struct RdapBootstrap {
    services: Vec<Vec<serde_json::Value>>,
}

async fn get_rdap_servers(client: &Client) -> Result<HashMap<String, String>, String> {
    let cache = RDAP_CACHE.get_or_init(|| Mutex::new(None));
    let mut guard = cache.lock().await;

    if let Some(ref map) = *guard {
        return Ok(map.clone());
    }

    let resp = client
        .get("https://data.iana.org/rdap/dns.json")
        .send()
        .await
        .map_err(|e| format!("Failed to fetch RDAP bootstrap: {e}"))?;

    let bootstrap: RdapBootstrap = resp
        .json()
        .await
        .map_err(|e| format!("Failed to parse RDAP bootstrap: {e}"))?;

    let mut map = HashMap::new();
    for service in &bootstrap.services {
        if service.len() >= 2
            && let (Some(tlds), Some(urls)) = (service[0].as_array(), service[1].as_array())
            && let Some(url) = urls.first().and_then(|u| u.as_str())
        {
            let base = url.trim_end_matches('/').to_string();
            for tld in tlds {
                if let Some(t) = tld.as_str() {
                    map.insert(t.to_lowercase(), base.clone());
                }
            }
        }
    }

    *guard = Some(map.clone());
    Ok(map)
}

fn extract_tld(domain: &str) -> Option<&str> {
    domain.rsplit('.').next()
}

#[derive(Deserialize)]
struct RdapDomain {
    #[serde(default)]
    entities: Vec<RdapEntity>,
}

#[derive(Deserialize)]
struct RdapEntity {
    #[serde(default)]
    roles: Vec<String>,
    #[serde(default)]
    handle: Option<String>,
}

fn extract_registrar(domain_obj: &RdapDomain) -> Option<String> {
    for entity in &domain_obj.entities {
        if entity.roles.contains(&"registrar".to_string()) {
            // Try to get name from handle or vcard
            if let Some(ref handle) = entity.handle {
                return Some(handle.clone());
            }
        }
    }
    None
}

pub async fn lookup(domain: &str) -> Result<RdapInfo, String> {
    let tld = extract_tld(domain).ok_or_else(|| "Invalid domain: no TLD".to_string())?;

    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| format!("HTTP client error: {e}"))?;

    let servers = get_rdap_servers(&client).await?;
    let base_url = servers
        .get(&tld.to_lowercase())
        .ok_or_else(|| format!("No RDAP server known for TLD: .{tld}"))?;

    let url = format!("{base_url}/domain/{domain}");

    let resp = client
        .get(&url)
        .header("Accept", "application/rdap+json")
        .send()
        .await
        .map_err(|e| format!("RDAP request failed: {e}"))?;

    let status_code = resp.status().as_u16();

    if status_code == 404 {
        return Ok(RdapInfo {
            status_code,
            found: false,
            registrar: None,
        });
    }

    if !resp.status().is_success() {
        return Ok(RdapInfo {
            status_code,
            found: false,
            registrar: None,
        });
    }

    let domain_obj: RdapDomain = resp
        .json()
        .await
        .map_err(|e| format!("Failed to parse RDAP response: {e}"))?;

    let registrar = extract_registrar(&domain_obj);

    Ok(RdapInfo {
        status_code,
        found: true,
        registrar,
    })
}
