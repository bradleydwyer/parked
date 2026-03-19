use crate::types::{ProbeInfo, SiteClassification};
use reqwest::redirect::Policy;
use std::time::Duration;

pub async fn classify(domain: &str) -> ProbeInfo {
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(4))
        .redirect(Policy::limited(5))
        .danger_accept_invalid_certs(true)
        .user_agent("Mozilla/5.0 (compatible; parked/2.2)")
        .build()
    {
        Ok(c) => c,
        Err(_) => {
            return ProbeInfo {
                classification: SiteClassification::Unreachable,
                final_url: None,
                status_code: None,
                reason: "Failed to build HTTP client".into(),
            };
        }
    };

    // Try HTTPS first, fall back to HTTP on connection error
    let response = match client.get(format!("https://{domain}")).send().await {
        Ok(resp) => resp,
        Err(e) if e.is_connect() => match client.get(format!("http://{domain}")).send().await {
            Ok(resp) => resp,
            Err(_) => {
                return ProbeInfo {
                    classification: SiteClassification::Unreachable,
                    final_url: None,
                    status_code: None,
                    reason: "Connection failed (HTTPS and HTTP)".into(),
                };
            }
        },
        Err(_) => {
            return ProbeInfo {
                classification: SiteClassification::Unreachable,
                final_url: None,
                status_code: None,
                reason: "Request failed".into(),
            };
        }
    };

    let status = response.status().as_u16();
    let final_url = response.url().to_string();

    // Check for cross-domain redirect
    if is_different_domain(domain, &final_url) {
        return ProbeInfo {
            classification: SiteClassification::Redirect,
            final_url: Some(final_url),
            status_code: Some(status),
            reason: "Redirects to different domain".into(),
        };
    }

    // Read body (limited to 64KB)
    let body = match response.text().await {
        Ok(text) => {
            if text.len() > 65536 {
                text[..65536].to_string()
            } else {
                text
            }
        }
        Err(_) => {
            return ProbeInfo {
                classification: SiteClassification::Unreachable,
                final_url: Some(final_url),
                status_code: Some(status),
                reason: "Failed to read response body".into(),
            };
        }
    };

    let (classification, reason) = classify_body(&body);

    ProbeInfo {
        classification,
        final_url: Some(final_url),
        status_code: Some(status),
        reason,
    }
}

fn is_different_domain(original: &str, final_url: &str) -> bool {
    let original_base = base_domain(original);
    let final_base = final_url
        .split("//")
        .nth(1)
        .and_then(|s| s.split('/').next())
        .map(base_domain)
        .unwrap_or_default();

    !original_base.is_empty() && !final_base.is_empty() && original_base != final_base
}

fn base_domain(host: &str) -> String {
    // Strip port if present
    let host = host.split(':').next().unwrap_or(host);
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() >= 2 {
        format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1])
    } else {
        host.to_lowercase()
    }
}

fn classify_body(body: &str) -> (SiteClassification, String) {
    let body_len = body.len();
    let lower = body.to_lowercase();

    // Known parking service signatures
    let parking_signatures: &[(&str, &str)] = &[
        ("sedoparking", "Sedo parking page"),
        ("parkingcrew", "ParkingCrew parking page"),
        ("domaincontrol.com", "GoDaddy parking"),
        ("parking.godaddy.com", "GoDaddy parking"),
        ("hugedomains.com", "HugeDomains listing"),
        ("dan.com", "Dan.com marketplace"),
        ("afternic.com", "Afternic listing"),
        ("bodis.com", "Bodis parking page"),
        ("above.com", "Above.com parking"),
        ("undeveloped.com", "Undeveloped marketplace"),
        ("domainlore.co.uk", "DomainLore parking"),
        ("namecheap.com/domains", "Namecheap parking"),
        ("domainmarket.com", "Domain Market listing"),
        ("squadhelp.com", "Squadhelp marketplace"),
        ("brandpa.com", "Brandpa marketplace"),
        ("uni-parking", "Uni parking page"),
        ("parklogic", "ParkLogic parking"),
        ("domainsponsor", "DomainSponsor parking"),
    ];

    for (sig, reason) in parking_signatures {
        if lower.contains(sig) {
            return (SiteClassification::Parked, reason.to_string());
        }
    }

    // "For sale" patterns
    let sale_patterns: &[&str] = &[
        "this domain is for sale",
        "this domain name is for sale",
        "domain is for sale",
        "domain for sale",
        "buy this domain",
        "make an offer",
        "domain may be for sale",
        "inquire about this domain",
        "purchase this domain",
        "domain is available for purchase",
        "get this domain",
        "this site is for sale",
    ];

    for pattern in sale_patterns {
        if lower.contains(pattern) {
            return (SiteClassification::Parked, "Domain for sale page".into());
        }
    }

    // JS-only redirect with minimal content
    if body_len < 2000
        && (lower.contains("window.location") || lower.contains("document.location"))
        && strip_tags(&lower).trim().len() < 100
    {
        return (
            SiteClassification::Parked,
            "JavaScript redirect (likely tracking)".into(),
        );
    }

    // Minimal content check — but only if total HTML is also small.
    // JS-heavy SPAs (like google.com) have large HTML but little visible text.
    let text_content = strip_tags(&lower);
    let trimmed = text_content.trim();
    if trimmed.len() < 200 && body_len < 5000 {
        return (
            SiteClassification::Parked,
            "Minimal content (likely placeholder)".into(),
        );
    }

    (SiteClassification::Active, "Has substantial content".into())
}

fn strip_tags(html: &str) -> String {
    let mut result = String::with_capacity(html.len());
    let mut in_tag = false;
    let mut in_script = false;

    let bytes = html.as_bytes();
    let len = bytes.len();
    let mut i = 0;

    while i < len {
        if !in_tag && bytes[i] == b'<' {
            // Check for <script (compare bytes directly to avoid UTF-8 boundary issues)
            if i + 7 < len && &bytes[i..i + 7] == b"<script" {
                in_script = true;
            }
            // Check for </script>
            if i + 9 < len && &bytes[i..i + 9] == b"</script>" {
                in_script = false;
                i += 9;
                continue;
            }
            in_tag = true;
        } else if in_tag && bytes[i] == b'>' {
            in_tag = false;
        } else if !in_tag && !in_script {
            result.push(bytes[i] as char);
        }
        i += 1;
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sedo_parking() {
        let body = r#"<html><head><title>example.com</title></head><body><script src="https://sedoparking.com/foo.js"></script></body></html>"#;
        let (class, _) = classify_body(body);
        assert_eq!(class, SiteClassification::Parked);
    }

    #[test]
    fn test_godaddy_parking() {
        let body = r#"<html><body><iframe src="https://parking.godaddy.com/park?dom=example.com"></iframe></body></html>"#;
        let (class, _) = classify_body(body);
        assert_eq!(class, SiteClassification::Parked);
    }

    #[test]
    fn test_for_sale_page() {
        let body = r#"<html><body><h1>This domain is for sale</h1><p>Contact us to purchase.</p></body></html>"#;
        let (class, _) = classify_body(body);
        assert_eq!(class, SiteClassification::Parked);
    }

    #[test]
    fn test_js_redirect() {
        let body = r#"<html><head><script>window.location='https://tracking.example.com/redir?id=abc';</script></head><body></body></html>"#;
        let (class, reason) = classify_body(body);
        assert_eq!(class, SiteClassification::Parked);
        assert!(reason.contains("JavaScript redirect"));
    }

    #[test]
    fn test_minimal_content() {
        let body = r#"<html><head><meta charset="utf-8"></head><body></body></html>"#;
        let (class, _) = classify_body(body);
        assert_eq!(class, SiteClassification::Parked);
    }

    #[test]
    fn test_real_site() {
        let body = format!(
            "<html><head><title>Welcome</title></head><body>{}</body></html>",
            "Lorem ipsum dolor sit amet, consectetur adipiscing elit. ".repeat(20)
        );
        let (class, _) = classify_body(&body);
        assert_eq!(class, SiteClassification::Active);
    }

    #[test]
    fn test_different_domain() {
        assert!(is_different_domain("example.com", "https://other.com/page"));
        assert!(!is_different_domain(
            "example.com",
            "https://www.example.com/page"
        ));
        assert!(!is_different_domain(
            "example.com",
            "https://sub.example.com/"
        ));
        assert!(is_different_domain("foo.com", "https://bar.com/redirect"));
    }

    #[test]
    fn test_base_domain() {
        assert_eq!(base_domain("www.example.com"), "example.com");
        assert_eq!(base_domain("sub.deep.example.com"), "example.com");
        assert_eq!(base_domain("example.com"), "example.com");
        assert_eq!(base_domain("example.com:443"), "example.com");
    }

    #[test]
    fn test_strip_tags() {
        assert_eq!(strip_tags("<b>hello</b>"), "hello");
        assert_eq!(strip_tags("<script>var x=1;</script>visible"), "visible");
        assert_eq!(strip_tags("<div><p>text</p></div>"), "text");
    }
}
