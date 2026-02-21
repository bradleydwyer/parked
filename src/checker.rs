use crate::types::*;
use crate::{dns, rdap, whois};
use std::time::Instant;
use tokio::sync::Semaphore;
use std::sync::Arc;

pub async fn check_domain(domain: &str) -> DomainResult {
    let start = Instant::now();
    let domain = domain.trim().to_lowercase();
    let mut details = TierDetails::default();

    // Tier 1: DNS
    match dns::lookup(&domain).await {
        Ok(dns_info) => {
            let has_records = dns_info.has_records;
            details.dns = Some(dns_info);
            if has_records {
                return DomainResult {
                    domain,
                    available: Availability::Registered,
                    determined_by: Tier::Dns,
                    details,
                    elapsed_ms: start.elapsed().as_millis() as u64,
                };
            }
        }
        Err(_) => {
            // DNS lookup failed entirely, continue to next tier
        }
    }

    // Tier 2: WHOIS
    match whois::lookup(&domain).await {
        Ok(whois_info) => {
            let found = whois_info.found;
            details.whois = Some(whois_info);
            if found {
                return DomainResult {
                    domain,
                    available: Availability::Registered,
                    determined_by: Tier::Whois,
                    details,
                    elapsed_ms: start.elapsed().as_millis() as u64,
                };
            }
        }
        Err(_) => {
            // WHOIS failed, continue to RDAP
        }
    }

    // Tier 3: RDAP
    match rdap::lookup(&domain).await {
        Ok(rdap_info) => {
            let found = rdap_info.found;
            details.rdap = Some(rdap_info);
            if found {
                return DomainResult {
                    domain,
                    available: Availability::Registered,
                    determined_by: Tier::Rdap,
                    details,
                    elapsed_ms: start.elapsed().as_millis() as u64,
                };
            }
            // RDAP says not found → available
            DomainResult {
                domain,
                available: Availability::Available,
                determined_by: Tier::Rdap,
                details,
                elapsed_ms: start.elapsed().as_millis() as u64,
            }
        }
        Err(_) => {
            // All tiers failed or inconclusive
            DomainResult {
                domain,
                available: Availability::Unknown,
                determined_by: Tier::Rdap,
                details,
                elapsed_ms: start.elapsed().as_millis() as u64,
            }
        }
    }
}

pub async fn check_domains(domains: &[String]) -> Vec<DomainResult> {
    let semaphore = Arc::new(Semaphore::new(10));
    let mut handles = Vec::new();

    for domain in domains {
        let domain = domain.clone();
        let sem = Arc::clone(&semaphore);
        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();
            check_domain(&domain).await
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
