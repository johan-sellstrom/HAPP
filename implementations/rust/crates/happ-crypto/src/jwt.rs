use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, TokenData, Validation};
use serde::{de::DeserializeOwned, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum JwtError {
    #[error("jwt: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),

    #[error("encode not available (codec created in decode-only mode)")]
    EncodeUnavailable,

    #[error("unsupported signing algorithm: {0}")]
    UnsupportedAlg(String),
}

#[derive(Clone, Debug)]
pub enum JwtSigningAlg {
    RS256,
    HS256,
}

impl JwtSigningAlg {
    pub fn to_alg(&self) -> Algorithm {
        match self {
            JwtSigningAlg::RS256 => Algorithm::RS256,
            JwtSigningAlg::HS256 => Algorithm::HS256,
        }
    }
}

#[derive(Clone)]
pub struct JwtCodec {
    alg: JwtSigningAlg,
    enc: Option<EncodingKey>,
    dec: DecodingKey,
}

#[derive(Debug)]
pub struct VerifiedJwt<T> {
    pub token_data: TokenData<T>,
}

impl JwtCodec {
    pub fn from_hs256(secret: &[u8]) -> Result<Self, JwtError> {
        Ok(JwtCodec {
            alg: JwtSigningAlg::HS256,
            enc: Some(EncodingKey::from_secret(secret)),
            dec: DecodingKey::from_secret(secret),
        })
    }

    pub fn decoder_hs256(secret: &[u8]) -> Result<Self, JwtError> {
        Ok(JwtCodec {
            alg: JwtSigningAlg::HS256,
            enc: None,
            dec: DecodingKey::from_secret(secret),
        })
    }

    pub fn from_rs256_pem(private_pem: &[u8], public_pem: &[u8]) -> Result<Self, JwtError> {
        Ok(JwtCodec {
            alg: JwtSigningAlg::RS256,
            enc: Some(EncodingKey::from_rsa_pem(private_pem)?),
            dec: DecodingKey::from_rsa_pem(public_pem)?,
        })
    }

    pub fn decoder_rs256_pem(public_pem: &[u8]) -> Result<Self, JwtError> {
        Ok(JwtCodec {
            alg: JwtSigningAlg::RS256,
            enc: None,
            dec: DecodingKey::from_rsa_pem(public_pem)?,
        })
    }

    pub fn encode<T: Serialize>(&self, claims: &T) -> Result<String, JwtError> {
        let enc = self.enc.as_ref().ok_or(JwtError::EncodeUnavailable)?;
        let mut header = Header::new(self.alg.to_alg());
        header.typ = Some("JWT".to_string());
        Ok(encode(&header, claims, enc)?)
    }

    pub fn decode<T: DeserializeOwned>(&self, token: &str, audience: Option<&str>) -> Result<VerifiedJwt<T>, JwtError> {
        let mut validation = Validation::new(self.alg.to_alg());
        validation.validate_exp = false; // RP verifier enforces exp/iat policy explicitly
        if let Some(aud) = audience {
            validation.set_audience(&[aud]);
        }
        let td = decode::<T>(token, &self.dec, &validation)?;
        Ok(VerifiedJwt { token_data: td })
    }

    pub fn alg(&self) -> &JwtSigningAlg {
        &self.alg
    }
}
