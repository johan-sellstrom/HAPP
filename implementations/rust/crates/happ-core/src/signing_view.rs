use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::types::ActionIntent;

/// Deterministic representation of what was shown to the human.
///
/// HAPP v0.2+ uses `presentation_hash` over this SigningView to enforce WYSIWYS:
/// *what you show is what you sign; what you sign is what executes*.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SigningView {
    pub version: String,
    pub audience: Value,
    pub agent: Value,
    pub action: Value,
    pub constraints: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
}

impl SigningView {
    /// Build a SigningView from an ActionIntent.
    ///
    /// If `intent.profile` is present and recognized, you may apply more specific display rules.
    /// This reference implementation uses a conservative Generic Profile:
    /// - include full action.parameters (canonical JSON)
    /// - include constraints and envelope
    pub fn from_intent(intent: &ActionIntent) -> Self {
        let audience = json!({
            "id": intent.audience.id,
            "name": intent.audience.name,
        });

        let agent = json!({
            "id": intent.agent.id,
            "name": intent.agent.name,
            "software": intent.agent.software,
        });

        let action = json!({
            "type": intent.action.action_type,
            "parameters": intent.action.parameters,
        });

        let constraints = json!({
            "expiresAt": intent.constraints.expires_at,
            "oneTime": intent.constraints.one_time,
            "maxUses": intent.constraints.max_uses,
            "envelope": intent.constraints.envelope,
        });

        SigningView {
            version: intent.version.clone(),
            audience,
            agent,
            action,
            constraints,
            profile: intent.profile.clone(),
        }
    }
}
