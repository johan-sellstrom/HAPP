use chrono::Utc;
use serde_json::Value;
use thiserror::Error;

use happ_core::{
    hash::intent_hash, hash::presentation_hash, signing_view::SigningView,
    types::ConsentCredentialClaims,
};
use happ_crypto::JwtCodec;

use crate::{
    policy::{ExpectedIdentity, RpPolicy},
    replay::ReplayCache,
};

#[derive(Debug, Error)]
pub enum VerifyError {
    #[error("jwt decode/verify failed: {0}")]
    Jwt(String),

    #[error("policy violation: {0}")]
    Policy(String),

    #[error("replay detected")]
    Replay,

    #[error("invalid binding: {0}")]
    Binding(String),
}

pub struct RpVerifier {
    jwt: JwtCodec,
    replay: ReplayCache,
}

impl RpVerifier {
    pub fn new(jwt: JwtCodec) -> Self {
        RpVerifier {
            jwt,
            replay: ReplayCache::new(),
        }
    }

    pub fn replay_cache(&self) -> &ReplayCache {
        &self.replay
    }

    pub fn verify(
        &self,
        intent: &happ_core::types::ActionIntent,
        credential_jwt: &str,
        expected_aud: &str,
        policy: &RpPolicy,
        expected_identity: Option<&ExpectedIdentity>,
    ) -> Result<ConsentCredentialClaims, VerifyError> {
        let td = self
            .jwt
            .decode::<ConsentCredentialClaims>(credential_jwt, None)
            .map_err(|e| VerifyError::Jwt(e.to_string()))?;

        let claims = td.token_data.claims;

        // exp/iat
        let now = Utc::now().timestamp();
        if claims.exp <= now {
            return Err(VerifyError::Policy("credential expired".to_string()));
        }
        if claims.iat > now + 60 {
            return Err(VerifyError::Policy(
                "credential iat in the future".to_string(),
            ));
        }

        // audience binding
        if claims.aud != expected_aud {
            return Err(VerifyError::Binding(format!(
                "aud mismatch (expected {expected_aud}, got {})",
                claims.aud
            )));
        }

        // intent hash binding
        let ih = intent_hash(intent);
        if claims.intent_hash != ih {
            return Err(VerifyError::Binding("intent_hash mismatch".to_string()));
        }

        // presentation hash binding
        let view = SigningView::from_intent(intent);
        let ph = presentation_hash(&view);
        if claims.presentation_hash != ph {
            return Err(VerifyError::Binding(
                "presentation_hash mismatch".to_string(),
            ));
        }

        // PoHP level
        if !claims.assurance.level.meets_minimum(&policy.min_pohp_level) {
            return Err(VerifyError::Policy(format!(
                "PoHP level {} is below required {}",
                claims.assurance.level, policy.min_pohp_level
            )));
        }

        // replay
        if policy.enforce_one_time_jti {
            let ok = self.replay_cache().check_and_mark(&claims.jti, claims.exp);
            if !ok {
                return Err(VerifyError::Replay);
            }
        }

        // identity policy
        match policy.identity_mode {
            happ_core::types::IdentityMode::None => {
                // ignore
            }
            happ_core::types::IdentityMode::Preferred => {
                // if present, verify basic
                if let Some(id) = &claims.identity_binding {
                    self.verify_identity(id, policy, expected_identity)?;
                }
            }
            happ_core::types::IdentityMode::Required => {
                let id = claims.identity_binding.as_ref().ok_or_else(|| {
                    VerifyError::Policy("identity required but missing".to_string())
                })?;
                self.verify_identity(id, policy, expected_identity)?;
            }
        }

        Ok(claims)
    }

    fn verify_identity(
        &self,
        id: &happ_core::types::IdentityBinding,
        policy: &RpPolicy,
        expected_identity: Option<&ExpectedIdentity>,
    ) -> Result<(), VerifyError> {
        if !policy.allowed_identity_schemes.is_empty()
            && !policy
                .allowed_identity_schemes
                .iter()
                .any(|s| s == &id.scheme)
        {
            return Err(VerifyError::Policy(
                "identity scheme not allowed".to_string(),
            ));
        }

        if policy.require_embedded_identity_evidence && !id.evidence.embedded {
            return Err(VerifyError::Policy(
                "embedded identity evidence required".to_string(),
            ));
        }

        // expected identity binding checks (enterprise context)
        if let Some(exp) = expected_identity {
            if exp.scheme != id.scheme {
                return Err(VerifyError::Binding("identity scheme mismatch".to_string()));
            }
            if let Some(tid) = &exp.tid {
                if id.subject.tid.as_deref() != Some(tid.as_str()) {
                    return Err(VerifyError::Binding("tid mismatch".to_string()));
                }
            }
            if let Some(oid) = &exp.oid {
                if id.subject.oid.as_deref() != Some(oid.as_str()) {
                    return Err(VerifyError::Binding("oid mismatch".to_string()));
                }
            }
            if let Some(sub) = &exp.sub {
                if id.subject.sub.as_deref() != Some(sub.as_str()) {
                    return Err(VerifyError::Binding("sub mismatch".to_string()));
                }
            }
        }

        // If evidence is embedded, self-verify the id_token signature using jwks.
        if id.evidence.embedded {
            let token = id.evidence.token.as_ref().ok_or_else(|| {
                VerifyError::Policy("embedded=true but token missing".to_string())
            })?;
            let jwks =
                id.evidence.jwks.as_ref().ok_or_else(|| {
                    VerifyError::Policy("embedded=true but jwks missing".to_string())
                })?;
            verify_embedded_oidc_token(token, jwks).map_err(|e| VerifyError::Policy(e))?;
        }

        Ok(())
    }
}

fn verify_embedded_oidc_token(token: &str, jwks: &Value) -> Result<(), String> {
    use jsonwebtoken::jwk::{Jwk, JwkSet};
    use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};

    let header = decode_header(token).map_err(|e| e.to_string())?;
    let kid = header.kid.ok_or_else(|| "missing kid".to_string())?;
    let jwk_set: JwkSet = serde_json::from_value(jwks.clone()).map_err(|e| e.to_string())?;
    let jwk: &Jwk = jwk_set
        .find(&kid)
        .ok_or_else(|| "kid not found in jwks".to_string())?;
    let key = DecodingKey::from_jwk(jwk).map_err(|e| e.to_string())?;

    let mut validation = Validation::new(Algorithm::RS256);
    validation.validate_exp = true;

    let _td = decode::<serde_json::Value>(token, &key, &validation).map_err(|e| e.to_string())?;
    Ok(())
}
