use crate::checker::{self, CheckOptions};
use rmcp::{
    ErrorData as McpError, ServerHandler, handler::server::tool::ToolRouter,
    handler::server::wrapper::Parameters, model::*, tool_handler, tool_router,
};
use schemars::JsonSchema;
use serde::Deserialize;

#[derive(Debug, Deserialize, JsonSchema)]
pub struct CheckDomainParams {
    #[schemars(description = "The domain name to check (e.g. \"example.com\")")]
    pub domain: String,
    #[schemars(
        description = "Whether to probe registered domains to classify them as active, parked, redirect, or unreachable (default: true)"
    )]
    pub probe: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct CheckDomainsParams {
    #[schemars(description = "List of domain names to check")]
    pub domains: Vec<String>,
    #[schemars(
        description = "Whether to probe registered domains to classify them as active, parked, redirect, or unreachable (default: true)"
    )]
    pub probe: Option<bool>,
}

pub struct ParkedMcp {
    tool_router: ToolRouter<Self>,
}

impl Default for ParkedMcp {
    fn default() -> Self {
        Self::new()
    }
}

#[tool_router]
impl ParkedMcp {
    pub fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }

    #[rmcp::tool(
        description = "Check if a domain name is available for registration. Uses a tiered approach: DNS lookup first, then WHOIS, then RDAP. For registered domains, probes the site to classify it as active, parked, redirect, or unreachable."
    )]
    async fn check_domain(
        &self,
        Parameters(params): Parameters<CheckDomainParams>,
    ) -> Result<CallToolResult, McpError> {
        let opts = CheckOptions {
            probe: params.probe.unwrap_or(true),
        };
        let result = checker::check_domain(&params.domain, &opts).await;
        let json = serde_json::to_string_pretty(&result)
            .map_err(|e| McpError::internal_error(format!("Serialization error: {e}"), None))?;
        Ok(CallToolResult::success(vec![Content::text(json)]))
    }

    #[rmcp::tool(
        description = "Check multiple domain names for availability. Runs lookups concurrently. For registered domains, probes the site to classify it as active, parked, redirect, or unreachable."
    )]
    async fn check_domains(
        &self,
        Parameters(params): Parameters<CheckDomainsParams>,
    ) -> Result<CallToolResult, McpError> {
        if params.domains.is_empty() {
            return Err(McpError::invalid_params(
                "domains list cannot be empty",
                None,
            ));
        }
        if params.domains.len() > 50 {
            return Err(McpError::invalid_params(
                "Maximum 50 domains per request",
                None,
            ));
        }
        let opts = CheckOptions {
            probe: params.probe.unwrap_or(true),
        };
        let results = checker::check_domains(&params.domains, &opts).await;
        let json = serde_json::to_string_pretty(&results)
            .map_err(|e| McpError::internal_error(format!("Serialization error: {e}"), None))?;
        Ok(CallToolResult::success(vec![Content::text(json)]))
    }
}

#[tool_handler]
impl ServerHandler for ParkedMcp {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            instructions: Some(
                "Domain availability checker. Use check_domain for a single domain \
                 or check_domains for bulk lookups. Results include availability status, \
                 which tier (DNS/WHOIS/RDAP) determined the result, and for registered \
                 domains, a site classification (active, parked, redirect, or unreachable)."
                    .into(),
            ),
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            server_info: Implementation::from_build_env(),
            ..Default::default()
        }
    }
}
