use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Audience {
    pub id: Option<String>,
    pub name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Agent {
    pub id: Option<String>,
    pub name: Option<String>,
    pub software: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Action {
    #[serde(rename = "type")]
    pub action_type: Option<String>,
    pub parameters: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Constraints {
    #[serde(rename = "expiresAt")]
    pub expires_at: Option<String>,
    #[serde(rename = "oneTime")]
    pub one_time: Option<bool>,
    #[serde(rename = "maxUses")]
    pub max_uses: Option<u32>,
    pub envelope: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Display {
    pub title: Option<String>,
    pub summary: Option<String>,
    #[serde(rename = "riskNotice")]
    pub risk_notice: Option<String>,
    pub language: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionIntent {
    pub profile: Option<String>,
    pub audience: Option<Audience>,
    pub agent: Option<Agent>,
    pub action: Option<Action>,
    pub constraints: Option<Constraints>,
    pub display: Option<Display>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningView {
    pub profile: String,
    pub audience: Audience,
    pub agent: Agent,
    pub action: Action,
    pub constraints: Constraints,
    pub display: Display,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Assurance {
    pub level: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityBinding {
    pub scheme: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HappClaims {
    pub aud: Option<String>,
    pub exp: Option<i64>,
    pub iat: Option<i64>,
    #[serde(rename = "intent_hash")]
    pub intent_hash: Option<String>,
    #[serde(rename = "presentation_hash")]
    pub presentation_hash: Option<String>,
    pub assurance: Option<Assurance>,
    #[serde(rename = "identityBinding")]
    pub identity_binding: Option<IdentityBinding>,
    #[serde(rename = "challengeId")]
    pub challenge_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct VerifyOptions {
    pub expected_aud: String,
    pub now_epoch_seconds: Option<i64>,
    pub min_pohp_level: Option<String>,
    pub identity_required: bool,
    pub allowed_identity_schemes: Vec<String>,
    pub expected_challenge_id: Option<String>,
}
