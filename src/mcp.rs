use crate::checker;
use rmcp::{
    ErrorData as McpError, ServerHandler,
    handler::server::tool::ToolRouter,
    handler::server::wrapper::Parameters,
    model::*,
    tool_handler, tool_router,
};
use schemars::JsonSchema;
use serde::Deserialize;

#[derive(Debug, Deserialize, JsonSchema)]
pub struct CheckDomainParams {
    #[schemars(description = "The domain name to check (e.g. \"example.com\")")]
    pub domain: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct CheckDomainsParams {
    #[schemars(description = "List of domain names to check")]
    pub domains: Vec<String>,
}

pub struct DomainCheckMcp {
    tool_router: ToolRouter<Self>,
}

impl Default for DomainCheckMcp {
    fn default() -> Self {
        Self::new()
    }
}

#[tool_router]
impl DomainCheckMcp {
    pub fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }

    #[rmcp::tool(description = "Check if a domain name is available for registration. Uses a tiered approach: DNS lookup first, then WHOIS, then RDAP for definitive results.")]
    async fn check_domain(
        &self,
        Parameters(params): Parameters<CheckDomainParams>,
    ) -> Result<CallToolResult, McpError> {
        let result = checker::check_domain(&params.domain).await;
        let json = serde_json::to_string_pretty(&result)
            .map_err(|e| McpError::internal_error(format!("Serialization error: {e}"), None))?;
        Ok(CallToolResult::success(vec![Content::text(json)]))
    }

    #[rmcp::tool(description = "Check multiple domain names for availability. Runs lookups concurrently for efficiency.")]
    async fn check_domains(
        &self,
        Parameters(params): Parameters<CheckDomainsParams>,
    ) -> Result<CallToolResult, McpError> {
        if params.domains.is_empty() {
            return Err(McpError::invalid_params("domains list cannot be empty", None));
        }
        if params.domains.len() > 50 {
            return Err(McpError::invalid_params(
                "Maximum 50 domains per request",
                None,
            ));
        }
        let results = checker::check_domains(&params.domains).await;
        let json = serde_json::to_string_pretty(&results)
            .map_err(|e| McpError::internal_error(format!("Serialization error: {e}"), None))?;
        Ok(CallToolResult::success(vec![Content::text(json)]))
    }
}

#[tool_handler]
impl ServerHandler for DomainCheckMcp {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            instructions: Some(
                "Domain availability checker. Use check_domain for a single domain \
                 or check_domains for bulk lookups. Results include availability status \
                 and which tier (DNS/WHOIS/RDAP) determined the result."
                    .into(),
            ),
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            server_info: Implementation::from_build_env(),
            ..Default::default()
        }
    }
}
