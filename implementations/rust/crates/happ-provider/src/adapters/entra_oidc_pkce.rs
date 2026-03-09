use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{TimeZone, Utc};
use rand::{distributions::Alphanumeric, Rng};
use serde::Deserialize;
use serde_json::Value;
use url::Url;

use happ_core::{
    types::{
        IdentityAssurance, IdentityBinding, IdentityEvidence, IdentityIdp, IdentityPolicy,
        IdentityRequirements, IdentitySubject,
    },
    HappError, HappResult,
};
use happ_crypto::util::sha256_base64url_nopad;

use crate::adapters::{IdentityAdapter, IdentityAdapterOutcome};
use crate::provider::{OidcTempState, Provider, Session};

#[derive(Clone, Debug)]
pub struct EntraOidcConfig {
    /// Tenant id or special values: common, organizations, consumers
    pub tenant: String,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub redirect_base: String, // e.g. http://127.0.0.1:8787
}

impl EntraOidcConfig {
    pub fn issuer(&self) -> String {
        format!("https://login.microsoftonline.com/{}/v2.0", self.tenant)
    }

    pub fn authorize_endpoint(&self) -> String {
        format!(
            "https://login.microsoftonline.com/{}/oauth2/v2.0/authorize",
            self.tenant
        )
    }

    pub fn token_endpoint(&self) -> String {
        format!(
            "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
            self.tenant
        )
    }

    pub fn jwks_endpoint(&self) -> String {
        format!(
            "https://login.microsoftonline.com/{}/discovery/v2.0/keys",
            self.tenant
        )
    }

    pub fn redirect_uri(&self) -> String {
        format!(
            "{}/identity/entra_oidc/callback",
            self.redirect_base.trim_end_matches('/')
        )
    }
}

/// Microsoft Entra ID OIDC adapter (Authorization Code + PKCE).
///
/// This is an interoperable identity-binding adapter that yields `tid+oid` subject binding.
pub struct EntraOidcPkceAdapter {
    pub cfg: EntraOidcConfig,
    http: reqwest::Client,
}

impl EntraOidcPkceAdapter {
    pub fn new(cfg: EntraOidcConfig) -> Self {
        EntraOidcPkceAdapter {
            cfg,
            http: reqwest::Client::new(),
        }
    }

    fn random_string(len: usize) -> String {
        rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(len)
            .map(char::from)
            .collect()
    }

    fn build_pkce(verifier: &str) -> String {
        // S256: BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))
        sha256_base64url_nopad(verifier.as_bytes())
    }

    async fn fetch_jwks(&self) -> HappResult<Value> {
        let jwks_url = self.cfg.jwks_endpoint();
        let v = self
            .http
            .get(jwks_url)
            .send()
            .await
            .map_err(|e| HappError::Io(e.to_string()))?
            .json::<Value>()
            .await
            .map_err(|e| HappError::Io(e.to_string()))?;
        Ok(v)
    }

    fn find_session_by_state(provider: &Provider, state: &str) -> Option<String> {
        for s in provider.list_sessions() {
            if let Some(oidc) = &s.oidc {
                if oidc.csrf == state && oidc.scheme == "entra_oidc" {
                    return Some(s.session_id.clone());
                }
            }
        }
        None
    }

    fn policy_from_req(req: &IdentityRequirements) -> IdentityPolicy {
        req.policy.clone().unwrap_or(IdentityPolicy {
            require_verified: true,
            require_embedded_evidence: false,
            allowed_tenants: vec![],
            max_id_age_seconds: None,
            require_mfa: false,
            required_auth_contexts: vec![],
            allow_asserted: false,
        })
    }
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    #[serde(rename = "access_token")]
    _access_token: Option<String>,
    id_token: Option<String>,
    #[serde(rename = "refresh_token")]
    _refresh_token: Option<String>,
    #[serde(rename = "expires_in")]
    _expires_in: Option<i64>,
    #[serde(rename = "scope")]
    _scope: Option<String>,
    #[serde(rename = "token_type")]
    _token_type: Option<String>,
}

#[async_trait]
impl IdentityAdapter for EntraOidcPkceAdapter {
    fn scheme(&self) -> &'static str {
        "entra_oidc"
    }

    async fn begin(
        &self,
        provider: Arc<Provider>,
        session: &Session,
        _req: &IdentityRequirements,
        _base_url: &str,
    ) -> HappResult<IdentityAdapterOutcome> {
        let csrf = Self::random_string(32);
        let nonce = Self::random_string(32);
        let pkce_verifier = Self::random_string(64);
        let pkce_challenge = Self::build_pkce(&pkce_verifier);

        provider.set_oidc_state(
            &session.session_id,
            OidcTempState {
                scheme: "entra_oidc".to_string(),
                csrf: csrf.clone(),
                nonce: nonce.clone(),
                pkce_verifier: pkce_verifier.clone(),
            },
        )?;

        let mut url = Url::parse(&self.cfg.authorize_endpoint())
            .map_err(|e| HappError::Invalid(e.to_string()))?;

        {
            let mut qp = url.query_pairs_mut();
            qp.append_pair("client_id", &self.cfg.client_id);
            qp.append_pair("response_type", "code");
            qp.append_pair("redirect_uri", &self.cfg.redirect_uri());
            qp.append_pair("response_mode", "query");
            qp.append_pair("scope", "openid profile email");
            qp.append_pair("state", &csrf);
            qp.append_pair("nonce", &nonce);
            qp.append_pair("code_challenge", &pkce_challenge);
            qp.append_pair("code_challenge_method", "S256");
            // Optional: enforce re-auth
            qp.append_pair("prompt", "select_account");
        }

        // NOTE: In a hardened implementation you may inject Entra auth context requirements
        // via claims challenge or other supported mechanisms. This reference keeps it minimal.
        // The RP expresses policy in req.policy.required_auth_contexts.

        Ok(IdentityAdapterOutcome::Redirect {
            url: url.to_string(),
        })
    }

    async fn handle_callback(
        &self,
        provider: Arc<Provider>,
        _session_id: &str,
        query: &HashMap<String, String>,
        _base_url: &str,
    ) -> HappResult<IdentityAdapterOutcome> {
        let code = query
            .get("code")
            .ok_or_else(|| HappError::Invalid("missing code".to_string()))?
            .clone();
        let state = query
            .get("state")
            .ok_or_else(|| HappError::Invalid("missing state".to_string()))?
            .clone();

        let sid = Self::find_session_by_state(&provider, &state)
            .ok_or_else(|| HappError::Invalid("unknown oidc state".to_string()))?;

        let session = provider
            .get_session(&sid)
            .ok_or_else(|| HappError::NotFound(format!("session {sid} not found")))?;

        let oidc = provider
            .take_oidc_state(&sid)?
            .ok_or_else(|| HappError::Invalid("missing oidc state".to_string()))?;

        if oidc.csrf != state {
            return Err(HappError::Unauthorized("state mismatch".to_string()));
        }

        let idreq = session
            .requirements
            .identity
            .clone()
            .ok_or_else(|| HappError::Invalid("identity not requested".to_string()))?;

        let policy = Self::policy_from_req(&idreq);

        // Exchange auth code for tokens
        let mut form: Vec<(&str, String)> = vec![
            ("client_id", self.cfg.client_id.clone()),
            ("grant_type", "authorization_code".to_string()),
            ("code", code.clone()),
            ("redirect_uri", self.cfg.redirect_uri()),
            ("code_verifier", oidc.pkce_verifier.clone()),
            ("scope", "openid profile email".to_string()),
        ];
        if let Some(secret) = &self.cfg.client_secret {
            form.push(("client_secret", secret.clone()));
        }

        let token_resp = self
            .http
            .post(self.cfg.token_endpoint())
            .form(&form)
            .send()
            .await
            .map_err(|e| HappError::Io(e.to_string()))?
            .json::<TokenResponse>()
            .await
            .map_err(|e| HappError::Io(e.to_string()))?;

        let id_token = token_resp
            .id_token
            .ok_or_else(|| HappError::Invalid("missing id_token".to_string()))?;

        // Fetch JWKS and validate token signature
        let jwks = self.fetch_jwks().await?;
        let expected_iss = match self.cfg.tenant.as_str() {
            "common" | "organizations" | "consumers" => None,
            _ => Some(self.cfg.issuer()),
        };

        let verified = verify_entra_id_token(
            &id_token,
            &jwks,
            expected_iss.as_deref(),
            &self.cfg.client_id,
            &oidc.nonce,
        )
        .map_err(|e| HappError::Unauthorized(e))?;

        // Extract tid+oid
        let tid = verified
            .tid
            .clone()
            .ok_or_else(|| HappError::Invalid("missing tid".to_string()))?;
        let oid = verified
            .oid
            .clone()
            .ok_or_else(|| HappError::Invalid("missing oid".to_string()))?;

        if !policy.allowed_tenants.is_empty() && !policy.allowed_tenants.contains(&tid) {
            return Err(HappError::Unauthorized("tenant not allowed".to_string()));
        }

        if policy.require_mfa {
            let amr = verified.amr.clone().unwrap_or_default();
            if !amr.iter().any(|x| x == "mfa") {
                return Err(HappError::Unauthorized(
                    "MFA required but not present".to_string(),
                ));
            }
        }

        if !policy.required_auth_contexts.is_empty() {
            let acrs = verified.acrs.clone().unwrap_or_default();
            for required in policy.required_auth_contexts.iter() {
                if !acrs.iter().any(|a| a == required) {
                    return Err(HappError::Unauthorized(format!(
                        "required auth context {required} not satisfied"
                    )));
                }
            }
        }

        // auth_time freshness
        if let (Some(max_age), Some(auth_time)) = (policy.max_id_age_seconds, verified.auth_time) {
            let age = Utc::now().timestamp() - auth_time;
            if age > max_age as i64 {
                return Err(HappError::Unauthorized("identity too old".to_string()));
            }
        }

        // Build identity binding
        let embedded = policy.require_embedded_evidence;
        let evidence = IdentityEvidence {
            kind: "oidc_id_token".to_string(),
            token_hash: Some(format!(
                "sha256:{}",
                sha256_base64url_nopad(id_token.as_bytes())
            )),
            nonce_hash: Some(format!(
                "sha256:{}",
                sha256_base64url_nopad(oidc.nonce.as_bytes())
            )),
            embedded,
            token: if embedded {
                Some(id_token.clone())
            } else {
                None
            },
            jwks: if embedded { Some(jwks.clone()) } else { None },
        };

        let assurance = IdentityAssurance {
            auth_time: verified
                .auth_time
                .map(|t| Utc.timestamp_opt(t, 0).single())
                .flatten(),
            amr: verified.amr.unwrap_or_default(),
            acrs: verified.acrs.unwrap_or_default(),
        };

        let binding = IdentityBinding {
            mode: "verified".to_string(),
            scheme: "entra_oidc".to_string(),
            idp: Some(IdentityIdp {
                issuer: self.cfg.issuer(),
                tenant_id: Some(tid.clone()),
            }),
            subject: IdentitySubject {
                subject_type: "entra_oid_tid".to_string(),
                tid: Some(tid),
                oid: Some(oid),
                sub: verified.sub,
                extra: Default::default(),
            },
            assurance: Some(assurance),
            evidence,
        };

        provider.set_identity(&sid, binding)?;

        // Redirect back to the session page.
        Ok(IdentityAdapterOutcome::Completed)
    }
}

/// Minimal verified fields from an Entra ID token.
#[derive(Debug, Clone)]
struct VerifiedEntraToken {
    sub: Option<String>,
    tid: Option<String>,
    oid: Option<String>,
    amr: Option<Vec<String>>,
    acrs: Option<Vec<String>>,
    auth_time: Option<i64>,
}

/// Verify an Entra ID token using a provided JWKS.
/// This is intentionally minimal and should be hardened for production use.
fn verify_entra_id_token(
    token: &str,
    jwks: &Value,
    expected_iss: Option<&str>,
    expected_aud: &str,
    expected_nonce: &str,
) -> Result<VerifiedEntraToken, String> {
    use jsonwebtoken::jwk::{Jwk, JwkSet};
    use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};

    let header = decode_header(token).map_err(|e| e.to_string())?;
    let kid = header.kid.ok_or_else(|| "missing kid".to_string())?;

    let jwk_set: JwkSet = serde_json::from_value(jwks.clone()).map_err(|e| e.to_string())?;
    let jwk: &Jwk = jwk_set
        .find(&kid)
        .ok_or_else(|| "kid not found in jwks".to_string())?;

    let decoding_key = DecodingKey::from_jwk(jwk).map_err(|e| e.to_string())?;

    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(&[expected_aud]);
    if let Some(iss) = expected_iss {
        validation.set_issuer(&[iss]);
    }
    validation.validate_exp = true;

    let td = decode::<serde_json::Value>(token, &decoding_key, &validation)
        .map_err(|e| e.to_string())?;
    let claims = td.claims;

    // nonce binding
    let nonce = claims
        .get("nonce")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "missing nonce".to_string())?;
    if nonce != expected_nonce {
        return Err("nonce mismatch".to_string());
    }

    Ok(VerifiedEntraToken {
        sub: claims
            .get("sub")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        tid: claims
            .get("tid")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        oid: claims
            .get("oid")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        amr: claims.get("amr").and_then(|v| v.as_array()).map(|arr| {
            arr.iter()
                .filter_map(|x| x.as_str().map(|s| s.to_string()))
                .collect()
        }),
        acrs: claims.get("acrs").and_then(|v| v.as_array()).map(|arr| {
            arr.iter()
                .filter_map(|x| x.as_str().map(|s| s.to_string()))
                .collect()
        }),
        auth_time: claims.get("auth_time").and_then(|v| v.as_i64()),
    })
}
