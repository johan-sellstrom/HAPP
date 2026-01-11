use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use uuid::Uuid;

use crate::level::PoHpLevel;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Party {
    pub id: String,
    pub name: String,
    #[serde(rename = "logoUrl", skip_serializing_if = "Option::is_none")]
    pub logo_url: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentSoftware {
    pub name: String,
    pub version: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Agent {
    pub id: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub software: Option<AgentSoftware>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Action {
    #[serde(rename = "type")]
    pub action_type: String,
    pub parameters: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Envelope {
    /// Envelope semantics are action-type-specific.
    /// This structure is intentionally open; RPs enforce these constraints deterministically.
    #[serde(flatten)]
    pub data: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Constraints {
    #[serde(rename = "expiresAt")]
    pub expires_at: DateTime<Utc>,
    #[serde(rename = "oneTime")]
    pub one_time: bool,
    #[serde(rename = "maxUses", skip_serializing_if = "Option::is_none")]
    pub max_uses: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub envelope: Option<Envelope>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Display {
    pub language: String,
    pub title: String,
    pub summary: String,
    #[serde(rename = "riskNotice", skip_serializing_if = "Option::is_none")]
    pub risk_notice: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Policy {
    #[serde(rename = "requiredPoHPLevel", skip_serializing_if = "Option::is_none")]
    pub required_pohp_level: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jurisdiction: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ActionIntent {
    pub version: String,
    #[serde(rename = "intentId")]
    pub intent_id: Uuid,
    #[serde(rename = "issuedAt")]
    pub issued_at: DateTime<Utc>,

    /// Optional profile identifier (e.g. aaif.happ.profile.payment.transfer/v0.2)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,

    pub audience: Party,
    pub agent: Agent,
    pub action: Action,
    pub constraints: Constraints,
    pub display: Display,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy: Option<Policy>,
}

/// HAPP Challenge (RP Challenge Mode)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HappChallenge {
    pub version: String,
    #[serde(rename = "challengeId")]
    pub challenge_id: String,
    #[serde(rename = "expiresAt")]
    pub expires_at: DateTime<Utc>,
    pub requirements: Requirements,
    #[serde(rename = "actionIntent")]
    pub action_intent: ActionIntent,
    #[serde(rename = "rpProof", skip_serializing_if = "Option::is_none")]
    pub rp_proof: Option<RpProof>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RpProof {
    /// RP signature/JWS over the challenge payload (optional).
    /// This is a placeholder field for future hardening.
    pub format: String,
    pub proof: String,
}

/// Requirements requested by RP/Host
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Requirements {
    pub pohp: PoHpRequirements,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity: Option<IdentityRequirements>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PoHpRequirements {
    #[serde(rename = "minLevel")]
    pub min_level: PoHpLevel,
    #[serde(rename = "maxCredentialAgeSeconds", skip_serializing_if = "Option::is_none")]
    pub max_credential_age_seconds: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum IdentityMode {
    #[serde(rename = "none")]
    None,
    #[serde(rename = "preferred")]
    Preferred,
    #[serde(rename = "required")]
    Required,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdentityRequirements {
    pub mode: IdentityMode,
    #[serde(default)]
    pub schemes: Vec<String>,
    #[serde(rename = "schemeParams", skip_serializing_if = "Option::is_none")]
    pub scheme_params: Option<BTreeMap<String, Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy: Option<IdentityPolicy>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdentityPolicy {
    #[serde(rename = "requireVerified", default)]
    pub require_verified: bool,
    #[serde(rename = "requireEmbeddedEvidence", default)]
    pub require_embedded_evidence: bool,
    #[serde(rename = "allowedTenants", default)]
    pub allowed_tenants: Vec<String>,
    #[serde(rename = "maxIdAgeSeconds", skip_serializing_if = "Option::is_none")]
    pub max_id_age_seconds: Option<u64>,
    #[serde(rename = "requireMfa", default)]
    pub require_mfa: bool,
    #[serde(rename = "requiredAuthContexts", default)]
    pub required_auth_contexts: Vec<String>,
    #[serde(rename = "allowAsserted", default)]
    pub allow_asserted: bool,
}

/// Signed consent credential envelope returned by a provider tool.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConsentCredentialEnvelope {
    pub format: String,
    pub credential: String,
    pub claims: ConsentCredentialClaims,
}

/// Claims carried in HAPP consent credentials.
/// This is a logical model that can be encoded as JWT or VC.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConsentCredentialClaims {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,

    #[serde(rename = "intent_hash")]
    pub intent_hash: String,

    #[serde(rename = "presentation_hash")]
    pub presentation_hash: String,

    pub aud: String,
    pub jti: String,
    pub iat: i64,
    pub exp: i64,

    pub assurance: Assurance,
    #[serde(rename = "providerCertification")]
    pub provider_certification: ProviderCertificationRef,

    #[serde(rename = "identityBinding", skip_serializing_if = "Option::is_none")]
    pub identity_binding: Option<IdentityBinding>,

    #[serde(rename = "challengeId", skip_serializing_if = "Option::is_none")]
    pub challenge_id: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Assurance {
    pub level: PoHpLevel,
    #[serde(rename = "verifiedAt")]
    pub verified_at: DateTime<Utc>,
    pub method: String,
    #[serde(rename = "deviceBinding", skip_serializing_if = "Option::is_none")]
    pub device_binding: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProviderCertificationRef {
    #[serde(rename = "ref")]
    pub reference: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub embedded: Option<String>,
}

/// Identity binding results.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdentityBinding {
    pub mode: String, // "verified" | "asserted"
    pub scheme: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idp: Option<IdentityIdp>,
    pub subject: IdentitySubject,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assurance: Option<IdentityAssurance>,
    pub evidence: IdentityEvidence,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdentityIdp {
    pub issuer: String,
    #[serde(rename = "tenantId", skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdentitySubject {
    #[serde(rename = "type")]
    pub subject_type: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub tid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oid: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,

    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdentityAssurance {
    #[serde(rename = "authTime", skip_serializing_if = "Option::is_none")]
    pub auth_time: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub amr: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub acrs: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdentityEvidence {
    pub kind: String, // e.g. "oidc_id_token"
    #[serde(rename = "tokenHash", skip_serializing_if = "Option::is_none")]
    pub token_hash: Option<String>,
    #[serde(rename = "nonceHash", skip_serializing_if = "Option::is_none")]
    pub nonce_hash: Option<String>,
    pub embedded: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks: Option<Value>,
}
