use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;

use happ_core::{types::IdentityRequirements, HappResult};

use crate::provider::{Provider, Session};

pub mod entra_mock;
pub mod entra_oidc_pkce;

#[derive(Clone, Debug)]
pub enum IdentityAdapterOutcome {
    /// The UI should redirect the user to the given URL (e.g., IdP login).
    Redirect { url: String },

    /// The UI should show a local action (e.g., "Use mock identity") linking to URL.
    LocalAction { url: String, label: String },

    /// Identity binding has been completed (either during begin or callback).
    Completed,
}

#[async_trait]
pub trait IdentityAdapter: Send + Sync {
    fn scheme(&self) -> &'static str;

    /// Begin an identity flow for a session. Returns an outcome indicating UI action.
    async fn begin(
        &self,
        provider: Arc<Provider>,
        session: &Session,
        req: &IdentityRequirements,
        base_url: &str,
    ) -> HappResult<IdentityAdapterOutcome>;

    /// Handle callback/return from the IdP (if applicable).
    async fn handle_callback(
        &self,
        provider: Arc<Provider>,
        session_id: &str,
        query: &HashMap<String, String>,
        base_url: &str,
    ) -> HappResult<IdentityAdapterOutcome>;
}

#[derive(Default)]
pub struct AdapterRegistry {
    adapters: HashMap<String, Arc<dyn IdentityAdapter>>,
}

impl AdapterRegistry {
    pub fn new() -> Self {
        AdapterRegistry {
            adapters: HashMap::new(),
        }
    }

    pub fn register(&mut self, adapter: Arc<dyn IdentityAdapter>) {
        self.adapters.insert(adapter.scheme().to_string(), adapter);
    }

    pub fn get(&self, scheme: &str) -> Option<Arc<dyn IdentityAdapter>> {
        self.adapters.get(scheme).cloned()
    }

    pub fn supported_schemes(&self) -> Vec<String> {
        self.adapters.keys().cloned().collect()
    }
}
