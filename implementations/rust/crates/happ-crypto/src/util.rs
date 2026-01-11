use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use sha2::{Digest, Sha256};

pub fn sha256_base64url_nopad(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    URL_SAFE_NO_PAD.encode(digest)
}
