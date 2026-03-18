use crate::types::DnsInfo;
use hickory_resolver::TokioResolver;
use hickory_resolver::proto::rr::RecordType;

pub async fn lookup(domain: &str) -> Result<DnsInfo, String> {
    let resolver = TokioResolver::builder_tokio()
        .map_err(|e| format!("Failed to create DNS resolver: {e}"))?
        .build();

    let mut record_types = Vec::new();

    // Check NS records first — most reliable indicator of registration
    if let Ok(response) = resolver.lookup(domain, RecordType::NS).await
        && response.iter().next().is_some()
    {
        record_types.push("NS".to_string());
    }

    // Also check A records as fallback
    if record_types.is_empty()
        && let Ok(response) = resolver.lookup(domain, RecordType::A).await
        && response.iter().next().is_some()
    {
        record_types.push("A".to_string());
    }

    // Check AAAA if still nothing
    if record_types.is_empty()
        && let Ok(response) = resolver.lookup(domain, RecordType::AAAA).await
        && response.iter().next().is_some()
    {
        record_types.push("AAAA".to_string());
    }

    let has_records = !record_types.is_empty();
    Ok(DnsInfo {
        has_records,
        record_types,
    })
}
