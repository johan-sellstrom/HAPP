use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Audience {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Agent {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub software: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Action {
    #[serde(rename = "type")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameters: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Constraints {
    #[serde(rename = "expiresAt")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(rename = "oneTime")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub one_time: Option<bool>,
    #[serde(rename = "maxUses")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_uses: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub envelope: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Display {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(rename = "riskNotice")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub risk_notice: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionIntent {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audience: Option<Audience>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent: Option<Agent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<Action>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub constraints: Option<Constraints>,
    #[serde(skip_serializing_if = "Option::is_none")]
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub level: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityBinding {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scheme: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HappClaims {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<i64>,
    #[serde(rename = "intent_hash")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub intent_hash: Option<String>,
    #[serde(rename = "presentation_hash")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub presentation_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assurance: Option<Assurance>,
    #[serde(rename = "identityBinding")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity_binding: Option<IdentityBinding>,
    #[serde(rename = "challengeId")]
    #[serde(skip_serializing_if = "Option::is_none")]
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
