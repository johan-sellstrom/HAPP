use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::Utc;
use serde_json::json;

use happ_core::{
    types::{
        IdentityAssurance, IdentityBinding, IdentityEvidence, IdentityIdp, IdentityRequirements, IdentitySubject,
    },
    HappError, HappResult,
};

use crate::adapters::{IdentityAdapter, IdentityAdapterOutcome};
use crate::provider::{Provider, Session};

/// Offline/mock adapter for enterprise identity binding.
/// This is intended for local development and conformance harness runs.
pub struct EntraMockAdapter;

impl EntraMockAdapter {
    pub fn new() -> Self {
        EntraMockAdapter
    }
}

#[async_trait]
impl IdentityAdapter for EntraMockAdapter {
    fn scheme(&self) -> &'static str {
        "entra_oidc"
    }

    async fn begin(
        &self,
        _provider: Arc<Provider>,
        session: &Session,
        _req: &IdentityRequirements,
        base_url: &str,
    ) -> HappResult<IdentityAdapterOutcome> {
        // Offer a local "complete" link which sets a deterministic tid+oid on the session.
        let url = format!(
            "{}/session/{}/identity/entra_oidc/mock_complete?tid={}&oid={}",
            base_url,
            session.session_id,
            "00000000-0000-0000-0000-000000000000",
            "11111111-1111-1111-1111-111111111111"
        );

        Ok(IdentityAdapterOutcome::LocalAction {
            url,
            label: "Use mock Entra identity (offline)".to_string(),
        })
    }

    async fn handle_callback(
        &self,
        provider: Arc<Provider>,
        session_id: &str,
        query: &HashMap<String, String>,
        _base_url: &str,
    ) -> HappResult<IdentityAdapterOutcome> {
        let tid = query
            .get("tid")
            .cloned()
            .unwrap_or_else(|| "00000000-0000-0000-0000-000000000000".to_string());
        let oid = query
            .get("oid")
            .cloned()
            .unwrap_or_else(|| "11111111-1111-1111-1111-111111111111".to_string());

        let binding = IdentityBinding {
            mode: "verified".to_string(),
            scheme: "entra_oidc".to_string(),
            idp: Some(IdentityIdp {
                issuer: "https://login.microsoftonline.com/common/v2.0".to_string(),
                tenant_id: Some(tid.clone()),
            }),
            subject: IdentitySubject {
                subject_type: "entra_oid_tid".to_string(),
                tid: Some(tid),
                oid: Some(oid),
                sub: None,
                extra: Default::default(),
            },
            assurance: Some(IdentityAssurance {
                auth_time: Some(Utc::now()),
                amr: vec!["mfa".to_string()],
                acrs: vec!["C1".to_string()],
            }),
            evidence: IdentityEvidence {
                kind: "oidc_id_token".to_string(),
                token_hash: None,
                nonce_hash: None,
                embedded: false,
                token: None,
                jwks: Some(json!({"keys": []})),
            },
        };

        provider.set_identity(session_id, binding)?;
        Ok(IdentityAdapterOutcome::Completed)
    }
}
