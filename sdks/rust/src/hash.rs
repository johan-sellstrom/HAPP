use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::Value;
use serde_json_canonicalizer::to_string as to_jcs_string;
use sha2::{Digest, Sha256};

use crate::types::{Action, ActionIntent, Agent, Audience, Constraints, Display, SigningView};

fn canonical_json(value: &Value) -> String {
    to_jcs_string(value).expect("serde_json::Value should be serializable as RFC 8785 JCS")
}

pub fn sha256_prefixed(value: &Value) -> String {
    let canonical = canonical_json(value);
    let digest = Sha256::digest(canonical.as_bytes());
    format!("sha256:{}", URL_SAFE_NO_PAD.encode(digest))
}

pub fn compute_intent_hash(action_intent: &ActionIntent) -> Result<String, serde_json::Error> {
    let v = serde_json::to_value(action_intent)?;
    Ok(sha256_prefixed(&v))
}

pub fn derive_signing_view(action_intent: &ActionIntent) -> SigningView {
    SigningView {
        profile: action_intent
            .profile
            .clone()
            .unwrap_or_else(|| "aaif.happ.profile.generic/v0.3".to_string()),
        audience: action_intent
            .audience
            .clone()
            .unwrap_or(Audience { id: None, name: None }),
        agent: action_intent.agent.clone().unwrap_or(Agent {
            id: None,
            name: None,
            software: None,
        }),
        action: action_intent.action.clone().unwrap_or(Action {
            action_type: None,
            parameters: None,
        }),
        constraints: action_intent.constraints.clone().unwrap_or(Constraints {
            expires_at: None,
            one_time: None,
            max_uses: None,
            envelope: None,
        }),
        display: action_intent.display.clone().unwrap_or(Display {
            title: None,
            summary: None,
            risk_notice: None,
            language: None,
        }),
    }
}

pub fn compute_presentation_hash(signing_view: &SigningView) -> Result<String, serde_json::Error> {
    let v = serde_json::to_value(signing_view)?;
    Ok(sha256_prefixed(&v))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn canonical_json_uses_rfc_8785_jcs() {
        let value = json!({
            "z": [3, null, "A\u{000f}"],
            "b": 1,
            "a": {
                "d": 4.5,
                "c": 0.002,
                "e": 1e30
            }
        });

        assert_eq!(
            canonical_json(&value),
            r#"{"a":{"c":0.002,"d":4.5,"e":1e+30},"b":1,"z":[3,null,"A\u000f"]}"#
        );
    }

    #[test]
    fn sha256_prefixed_is_stable_across_object_key_order() {
        let left = json!({
            "b": 1,
            "a": {
                "d": 4.5,
                "c": 0.002,
                "e": 1e30
            }
        });
        let right = json!({
            "a": {
                "c": 0.002,
                "e": 1e30,
                "d": 4.5
            },
            "b": 1
        });

        assert_eq!(sha256_prefixed(&left), sha256_prefixed(&right));
    }
}
