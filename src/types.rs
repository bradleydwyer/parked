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

#[derive(Debug, Clone, Serialize)]
pub struct DomainResult {
    pub domain: String,
    pub available: Availability,
    pub determined_by: Tier,
    pub details: TierDetails,
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
