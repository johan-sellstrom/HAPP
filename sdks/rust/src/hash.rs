use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use std::collections::BTreeMap;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::types::{Action, ActionIntent, Agent, Audience, Constraints, Display, SigningView};

fn canonical_json(value: &Value) -> String {
    // Pragmatic deterministic encoding for SDK interop in this repository.
    // The protocol spec requires RFC 8785 JCS for strict conformance.
    fn sort_value(v: &Value) -> Value {
        match v {
            Value::Object(map) => {
                let mut out = serde_json::Map::new();
                let mut sorted: BTreeMap<String, Value> = BTreeMap::new();
                for (k, v) in map {
                    sorted.insert(k.clone(), sort_value(v));
                }
                for (k, v) in sorted {
                    out.insert(k, v);
                }
                Value::Object(out)
            }
            Value::Array(items) => Value::Array(items.iter().map(sort_value).collect()),
            _ => v.clone(),
        }
    }

    serde_json::to_string(&sort_value(value)).unwrap_or_else(|_| "null".to_string())
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
