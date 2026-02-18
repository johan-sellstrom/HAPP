use std::time::{SystemTime, UNIX_EPOCH};

use thiserror::Error;

use crate::hash::{compute_intent_hash, compute_presentation_hash, derive_signing_view};
use crate::types::{ActionIntent, HappClaims, VerifyOptions};

#[derive(Debug, Error)]
pub enum VerifyError {
    #[error("aud mismatch")]
    AudMismatch,
    #[error("expired")]
    Expired,
    #[error("intent_hash mismatch")]
    IntentHashMismatch,
    #[error("presentation_hash mismatch")]
    PresentationHashMismatch,
    #[error("PoHP level too low")]
    PohpTooLow,
    #[error("identityBinding required")]
    IdentityRequired,
    #[error("identity scheme not allowed")]
    IdentitySchemeNotAllowed,
    #[error("challengeId mismatch")]
    ChallengeIdMismatch,
    #[error("serialization error: {0}")]
    Serialization(String),
}

fn pohp_rank(level: Option<&str>) -> i32 {
    match level {
        Some("AAIF-PoHP-1") => 1,
        Some("AAIF-PoHP-2") => 2,
        Some("AAIF-PoHP-3") => 3,
        Some("AAIF-PoHP-4") => 4,
        _ => 0,
    }
}

pub fn verify_claims(
    claims: &HappClaims,
    action_intent: &ActionIntent,
    options: &VerifyOptions,
) -> Result<(), VerifyError> {
    let now = options.now_epoch_seconds.unwrap_or_else(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64
    });

    if claims.aud.as_deref() != Some(options.expected_aud.as_str()) {
        return Err(VerifyError::AudMismatch);
    }

    match claims.exp {
        Some(exp) if exp >= now => {}
        _ => return Err(VerifyError::Expired),
    }

    let expected_intent_hash =
        compute_intent_hash(action_intent).map_err(|e| VerifyError::Serialization(e.to_string()))?;
    if claims.intent_hash.as_deref() != Some(expected_intent_hash.as_str()) {
        return Err(VerifyError::IntentHashMismatch);
    }

    let signing_view = derive_signing_view(action_intent);
    let expected_presentation_hash =
        compute_presentation_hash(&signing_view).map_err(|e| VerifyError::Serialization(e.to_string()))?;
    if claims.presentation_hash.as_deref() != Some(expected_presentation_hash.as_str()) {
        return Err(VerifyError::PresentationHashMismatch);
    }

    if let Some(min_level) = options.min_pohp_level.as_deref() {
        let got = claims.assurance.as_ref().and_then(|a| a.level.as_deref());
        if pohp_rank(got) < pohp_rank(Some(min_level)) {
            return Err(VerifyError::PohpTooLow);
        }
    }

    if options.identity_required && claims.identity_binding.is_none() {
        return Err(VerifyError::IdentityRequired);
    }

    if !options.allowed_identity_schemes.is_empty() {
        if let Some(id) = &claims.identity_binding {
            if let Some(scheme) = id.scheme.as_ref() {
                if !options.allowed_identity_schemes.iter().any(|s| s == scheme) {
                    return Err(VerifyError::IdentitySchemeNotAllowed);
                }
            }
        }
    }

    if let Some(expected_cid) = options.expected_challenge_id.as_deref() {
        if claims.challenge_id.as_deref() != Some(expected_cid) {
            return Err(VerifyError::ChallengeIdMismatch);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Action, Agent, Assurance, Audience, Constraints, Display};

    #[test]
    fn verifies_minimal_claims() {
        let intent = ActionIntent {
            profile: Some("test".to_string()),
            audience: Some(Audience {
                id: Some("did:web:rp.example".to_string()),
                name: Some("RP".to_string()),
            }),
            agent: Some(Agent {
                id: Some("agent:1".to_string()),
                name: Some("Agent".to_string()),
                software: None,
            }),
            action: Some(Action {
                action_type: Some("test.action".to_string()),
                parameters: None,
            }),
            constraints: Some(Constraints {
                expires_at: None,
                one_time: Some(true),
                max_uses: None,
                envelope: None,
            }),
            display: Some(Display {
                title: Some("T".to_string()),
                summary: Some("S".to_string()),
                risk_notice: None,
                language: Some("en".to_string()),
            }),
        };

        let intent_hash = compute_intent_hash(&intent).unwrap();
        let view = derive_signing_view(&intent);
        let pres_hash = compute_presentation_hash(&view).unwrap();

        let claims = HappClaims {
            aud: Some("did:web:rp.example".to_string()),
            exp: Some(9_999_999_999),
            iat: Some(1),
            intent_hash: Some(intent_hash),
            presentation_hash: Some(pres_hash),
            assurance: Some(Assurance {
                level: Some("AAIF-PoHP-3".to_string()),
            }),
            identity_binding: None,
            challenge_id: None,
        };

        let opts = VerifyOptions {
            expected_aud: "did:web:rp.example".to_string(),
            now_epoch_seconds: Some(100),
            min_pohp_level: Some("AAIF-PoHP-2".to_string()),
            identity_required: false,
            allowed_identity_schemes: vec![],
            expected_challenge_id: None,
        };

        verify_claims(&claims, &intent, &opts).expect("verification should pass");
    }
}
