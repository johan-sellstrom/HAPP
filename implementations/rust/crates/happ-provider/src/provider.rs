use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};
use dashmap::DashMap;
use serde::Serialize;
use uuid::Uuid;

use happ_core::{
    intent_hash, presentation_hash,
    signing_view::SigningView,
    types::{
        ActionIntent, ConsentCredentialClaims, ConsentCredentialEnvelope, IdentityMode,
        ProviderCertificationRef, Requirements,
    },
    Assurance, HappError, HappResult,
};
use happ_crypto::JwtCodec;

use crate::adapters::{AdapterRegistry, IdentityAdapterOutcome};

pub type SessionId = String;

#[derive(Clone, Debug, Serialize)]
pub enum SessionStatus {
    Pending,
    Denied,
    Approved,
}

#[derive(Clone, Debug, Serialize)]
pub struct Session {
    pub session_id: SessionId,
    pub request_id: String,
    pub aud: String,

    pub created_at: DateTime<Utc>,
    pub intent: ActionIntent,
    pub requirements: Requirements,
    pub challenge_id: Option<String>,

    pub status: SessionStatus,

    /// Optional identity binding result.
    pub identity: Option<happ_core::types::IdentityBinding>,

    /// Whether the user completed a PoHP (presence) step.
    pub pohp_verified_at: Option<DateTime<Utc>>,
    pub pohp_method: Option<String>,
    pub pohp_level: Option<happ_core::level::PoHpLevel>,
    pub issued_credential: Option<ConsentCredentialEnvelope>,

    /// Temporary OIDC state for identity adapters (e.g., Entra PKCE).
    pub oidc: Option<OidcTempState>,
}

#[derive(Clone, Debug, Serialize)]
pub struct OidcTempState {
    pub scheme: String,
    pub csrf: String,
    pub nonce: String,
    pub pkce_verifier: String,
}

#[derive(Clone)]
pub struct ProviderConfig {
    pub issuer: String,
    pub provider_cert: ProviderCertificationRef,
    pub credential_ttl_seconds: i64,
}

pub struct Provider {
    config: ProviderConfig,
    jwt: JwtCodec,
    sessions_by_id: DashMap<SessionId, Session>,
    session_by_request: DashMap<String, SessionId>,
    adapters: AdapterRegistry,
}

impl Provider {
    pub fn new(config: ProviderConfig, jwt: JwtCodec, adapters: AdapterRegistry) -> Arc<Self> {
        Arc::new(Provider {
            config,
            jwt,
            sessions_by_id: DashMap::new(),
            session_by_request: DashMap::new(),
            adapters,
        })
    }

    pub fn config(&self) -> &ProviderConfig {
        &self.config
    }

    pub fn jwt(&self) -> &JwtCodec {
        &self.jwt
    }

    pub fn adapters(&self) -> &AdapterRegistry {
        &self.adapters
    }

    pub fn get_session(&self, session_id: &str) -> Option<Session> {
        self.sessions_by_id.get(session_id).map(|s| s.clone())
    }

    pub fn list_sessions(&self) -> Vec<Session> {
        self.sessions_by_id.iter().map(|s| s.clone()).collect()
    }

    pub fn ensure_session(
        &self,
        request_id: &str,
        aud: &str,
        intent: ActionIntent,
        requirements: Requirements,
        challenge_id: Option<String>,
    ) -> HappResult<SessionId> {
        if let Some(existing) = self.session_by_request.get(request_id) {
            let sid = existing.value().clone();
            let session = self
                .sessions_by_id
                .get(&sid)
                .ok_or_else(|| HappError::NotFound(format!("session {sid} not found")))?;
            let existing_hash = intent_hash(&session.intent);
            let new_hash = intent_hash(&intent);
            if existing_hash != new_hash {
                return Err(HappError::Invalid(
                    "requestId reused with different intent_hash".to_string(),
                ));
            }
            return Ok(sid);
        }

        let sid = Uuid::new_v4().to_string();
        let session = Session {
            session_id: sid.clone(),
            request_id: request_id.to_string(),
            aud: aud.to_string(),
            created_at: Utc::now(),
            intent,
            requirements,
            challenge_id,
            status: SessionStatus::Pending,
            identity: None,
            pohp_verified_at: None,
            pohp_method: None,
            pohp_level: None,
            issued_credential: None,
            oidc: None,
        };

        self.sessions_by_id.insert(sid.clone(), session);
        self.session_by_request
            .insert(request_id.to_string(), sid.clone());
        Ok(sid)
    }

    pub fn deny(&self, session_id: &str) -> HappResult<()> {
        let mut s = self
            .sessions_by_id
            .get_mut(session_id)
            .ok_or_else(|| HappError::NotFound(format!("session {session_id} not found")))?;
        s.status = SessionStatus::Denied;
        Ok(())
    }

    pub fn mark_pohp_verified(
        &self,
        session_id: &str,
        method: impl Into<String>,
        level: happ_core::level::PoHpLevel,
        verified_at: Option<DateTime<Utc>>,
    ) -> HappResult<()> {
        let mut s = self
            .sessions_by_id
            .get_mut(session_id)
            .ok_or_else(|| HappError::NotFound(format!("session {session_id} not found")))?;
        s.pohp_verified_at = Some(verified_at.unwrap_or_else(Utc::now));
        s.pohp_method = Some(method.into());
        s.pohp_level = Some(level);
        Ok(())
    }

    pub fn set_identity(
        &self,
        session_id: &str,
        identity: happ_core::types::IdentityBinding,
    ) -> HappResult<()> {
        let mut s = self
            .sessions_by_id
            .get_mut(session_id)
            .ok_or_else(|| HappError::NotFound(format!("session {session_id} not found")))?;
        s.identity = Some(identity);
        Ok(())
    }

    pub fn set_oidc_state(&self, session_id: &str, state: OidcTempState) -> HappResult<()> {
        let mut s = self
            .sessions_by_id
            .get_mut(session_id)
            .ok_or_else(|| HappError::NotFound(format!("session {session_id} not found")))?;
        s.oidc = Some(state);
        Ok(())
    }

    pub fn take_oidc_state(&self, session_id: &str) -> HappResult<Option<OidcTempState>> {
        let mut s = self
            .sessions_by_id
            .get_mut(session_id)
            .ok_or_else(|| HappError::NotFound(format!("session {session_id} not found")))?;
        Ok(s.oidc.take())
    }

    pub fn approve(&self, session_id: &str) -> HappResult<()> {
        let mut s = self
            .sessions_by_id
            .get_mut(session_id)
            .ok_or_else(|| HappError::NotFound(format!("session {session_id} not found")))?;

        // Enforce identity.mode=required if present.
        if let Some(idreq) = &s.requirements.identity {
            if matches!(idreq.mode, IdentityMode::Required) && s.identity.is_none() {
                return Err(HappError::Unauthorized(
                    "identity binding required but not completed".to_string(),
                ));
            }
        }

        // Require PoHP completion (in this reference impl, a button sets pohp_verified_at).
        if s.pohp_verified_at.is_none() {
            return Err(HappError::Unauthorized(
                "presence verification not completed".to_string(),
            ));
        }

        let got_level = s.pohp_level.clone().ok_or_else(|| {
            HappError::Unauthorized("presence verification level missing".to_string())
        })?;
        if !got_level.meets_minimum(&s.requirements.pohp.min_level) {
            return Err(HappError::Unauthorized(
                "presence verification level below required minimum".to_string(),
            ));
        }

        s.status = SessionStatus::Approved;
        Ok(())
    }

    pub fn issue_credential(&self, session_id: &str) -> HappResult<ConsentCredentialEnvelope> {
        let mut session = self
            .sessions_by_id
            .get_mut(session_id)
            .ok_or_else(|| HappError::NotFound(format!("session {session_id} not found")))?;

        if !matches!(session.status, SessionStatus::Approved) {
            return Err(HappError::Unauthorized("session not approved".to_string()));
        }

        if let Some(existing) = &session.issued_credential {
            return Ok(existing.clone());
        }

        // Build intent and presentation hashes
        let ih = intent_hash(&session.intent);
        let view = SigningView::from_intent(&session.intent);
        let ph = presentation_hash(&view);

        let now = Utc::now();
        let iat = now.timestamp();
        let max_exp = now + Duration::seconds(self.config.credential_ttl_seconds);
        let exp = std::cmp::min(max_exp, session.intent.constraints.expires_at).timestamp();

        if exp <= iat {
            return Err(HappError::Expired(
                "intent/credential already expired".to_string(),
            ));
        }

        let verified_at = session.pohp_verified_at.unwrap_or(now);

        let pohp_method = session.pohp_method.clone().ok_or_else(|| {
            HappError::Invalid("presence verification method missing".to_string())
        })?;

        let assurance = Assurance {
            level: session.pohp_level.clone().ok_or_else(|| {
                HappError::Invalid("presence verification level missing".to_string())
            })?,
            verified_at,
            method: pohp_method,
            device_binding: None,
        };

        let claims = ConsentCredentialClaims {
            issuer: Some(self.config.issuer.clone()),
            subject: None,
            intent_hash: ih.clone(),
            presentation_hash: ph.clone(),
            aud: session.aud.clone(),
            jti: Uuid::new_v4().to_string(),
            iat,
            exp,
            assurance,
            provider_certification: self.config.provider_cert.clone(),
            identity_binding: session.identity.clone(),
            challenge_id: session.challenge_id.clone(),
        };

        let jwt = self
            .jwt
            .encode(&claims)
            .map_err(|e| HappError::Crypto(e.to_string()))?;

        let issued = ConsentCredentialEnvelope {
            format: "jwt".to_string(),
            credential: jwt,
            claims,
        };
        session.issued_credential = Some(issued.clone());
        Ok(issued)
    }

    /// Start an identity adapter flow for this session (if any).
    /// Returns an outcome describing what the UI should do next.
    pub async fn identity_begin(
        self: &Arc<Self>,
        session_id: &str,
        base_url: &str,
    ) -> HappResult<Option<IdentityAdapterOutcome>> {
        let session = self
            .sessions_by_id
            .get(session_id)
            .ok_or_else(|| HappError::NotFound(format!("session {session_id} not found")))?
            .clone();

        let idreq = match &session.requirements.identity {
            None => return Ok(None),
            Some(r) => r.clone(),
        };

        if matches!(idreq.mode, IdentityMode::None) {
            return Ok(None);
        }

        let schemes = if idreq.schemes.is_empty() {
            vec!["entra_oidc".to_string()]
        } else {
            idreq.schemes.clone()
        };

        for scheme in schemes {
            if let Some(adapter) = self.adapters.get(&scheme) {
                let outcome = adapter
                    .begin(self.clone(), &session, &idreq, base_url)
                    .await?;
                return Ok(Some(outcome));
            }
        }

        if matches!(idreq.mode, IdentityMode::Required) {
            return Err(HappError::Invalid(
                "identity required but no acceptable adapter available".to_string(),
            ));
        }

        Ok(None)
    }
}
