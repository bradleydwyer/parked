use serde::Serialize;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Availability {
    Available,
    Registered,
    Unknown,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Tier {
    Dns,
    Whois,
    Rdap,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SiteClassification {
    Parked,
    Active,
    Redirect,
    Unreachable,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProbeInfo {
    pub classification: SiteClassification,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub final_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_code: Option<u16>,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DomainResult {
    pub domain: String,
    pub available: Availability,
    pub determined_by: Tier,
    pub details: TierDetails,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub site: Option<ProbeInfo>,
    pub elapsed_ms: u64,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct TierDetails {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns: Option<DnsInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub whois: Option<WhoisInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rdap: Option<RdapInfo>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DnsInfo {
    pub has_records: bool,
    pub record_types: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct WhoisInfo {
    pub raw_response: String,
    pub registrar: Option<String>,
    pub creation_date: Option<String>,
    pub found: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct RdapInfo {
    pub status_code: u16,
    pub found: bool,
    pub registrar: Option<String>,
}

impl std::fmt::Display for Availability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Availability::Available => write!(f, "AVAILABLE"),
            Availability::Registered => write!(f, "REGISTERED"),
            Availability::Unknown => write!(f, "UNKNOWN"),
        }
    }
}

impl std::fmt::Display for Tier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Tier::Dns => write!(f, "dns"),
            Tier::Whois => write!(f, "whois"),
            Tier::Rdap => write!(f, "rdap"),
        }
    }
}

impl std::fmt::Display for SiteClassification {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SiteClassification::Parked => write!(f, "parked"),
            SiteClassification::Active => write!(f, "active"),
            SiteClassification::Redirect => write!(f, "redirect"),
            SiteClassification::Unreachable => write!(f, "unreachable"),
        }
    }
}
