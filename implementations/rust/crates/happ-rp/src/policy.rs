use happ_core::types::IdentityMode;
use happ_core::PoHpLevel;

#[derive(Clone, Debug)]
pub struct RpPolicy {
    pub min_pohp_level: PoHpLevel,
    pub identity_mode: IdentityMode,
    pub allowed_identity_schemes: Vec<String>,
    pub require_embedded_identity_evidence: bool,
    pub enforce_one_time_jti: bool,
}

impl Default for RpPolicy {
    fn default() -> Self {
        RpPolicy {
            min_pohp_level: PoHpLevel::L1,
            identity_mode: IdentityMode::None,
            allowed_identity_schemes: vec!["entra_oidc".to_string()],
            require_embedded_identity_evidence: false,
            enforce_one_time_jti: true,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ExpectedIdentity {
    pub scheme: String,
    pub tid: Option<String>,
    pub oid: Option<String>,
    pub sub: Option<String>,
}
