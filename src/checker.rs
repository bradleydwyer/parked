use crate::types::*;
use crate::{dns, probe, rdap, whois};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Semaphore;

#[derive(Debug, Clone)]
pub struct CheckOptions {
    pub probe: bool,
}

impl Default for CheckOptions {
    fn default() -> Self {
        Self { probe: true }
    }
}

async fn check_tiers(domain: &str) -> (Availability, Tier, TierDetails) {
    let mut details = TierDetails::default();

    // Tier 1: DNS
    if let Ok(dns_info) = dns::lookup(domain).await {
        let has_records = dns_info.has_records;
        details.dns = Some(dns_info);
        if has_records {
            return (Availability::Registered, Tier::Dns, details);
        }
    }

    // Tier 2: WHOIS
    if let Ok(whois_info) = whois::lookup(domain).await {
        let found = whois_info.found;
        details.whois = Some(whois_info);
        if found {
            return (Availability::Registered, Tier::Whois, details);
        } else {
            return (Availability::Available, Tier::Whois, details);
        }
    }

    // Tier 3: RDAP
    match rdap::lookup(domain).await {
        Ok(rdap_info) => {
            let found = rdap_info.found;
            details.rdap = Some(rdap_info);
            if found {
                (Availability::Registered, Tier::Rdap, details)
            } else {
                (Availability::Available, Tier::Rdap, details)
            }
        }
        Err(_) => (Availability::Unknown, Tier::Rdap, details),
    }
}

pub async fn check_domain(domain: &str, opts: &CheckOptions) -> DomainResult {
    let start = Instant::now();
    let domain = domain.trim().to_lowercase();

    let (available, determined_by, details) = check_tiers(&domain).await;

    let site = if opts.probe && available == Availability::Registered {
        Some(probe::classify(&domain).await)
    } else {
        None
    };

    DomainResult {
        domain,
        available,
        determined_by,
        details,
        site,
        elapsed_ms: start.elapsed().as_millis() as u64,
    }
}

pub async fn check_domains(domains: &[String], opts: &CheckOptions) -> Vec<DomainResult> {
    let semaphore = Arc::new(Semaphore::new(10));
    let mut handles = Vec::new();

    for domain in domains {
        let domain = domain.clone();
        let sem = Arc::clone(&semaphore);
        let opts = opts.clone();
        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();
            check_domain(&domain, &opts).await
        }));
    }

    let mut results = Vec::new();
    for handle in handles {
        if let Ok(result) = handle.await {
            results.push(result);
        }
    }
    results
}
