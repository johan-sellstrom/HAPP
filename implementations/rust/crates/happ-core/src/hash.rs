use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use sha2::{Digest, Sha256};

use crate::jcs::canonicalize_serde;
use crate::signing_view::SigningView;
use crate::types::ActionIntent;

/// Compute intent_hash = sha256(base64url_no_pad(SHA256(JCS(ActionIntent))))
pub fn intent_hash(intent: &ActionIntent) -> String {
    let canonical = canonicalize_serde(intent);
    let digest = Sha256::digest(canonical.as_bytes());
    format!("sha256:{}", URL_SAFE_NO_PAD.encode(digest))
}

/// Compute presentation_hash = sha256(base64url_no_pad(SHA256(JCS(SigningView))))
pub fn presentation_hash(view: &SigningView) -> String {
    let canonical = canonicalize_serde(view);
    let digest = Sha256::digest(canonical.as_bytes());
    format!("sha256:{}", URL_SAFE_NO_PAD.encode(digest))
}
