use serde::Serialize;
use serde_json::Value;

/// Canonicalize a serde_json::Value using RFC 8785 JSON Canonicalization Scheme.
pub fn canonicalize(value: &Value) -> String {
    serde_json_canonicalizer::to_string(value).expect("value to be serializable as JCS")
}

/// Convenience: canonicalize any serde-serializable object with RFC 8785 JCS.
pub fn canonicalize_serde<T: Serialize>(obj: &T) -> String {
    serde_json_canonicalizer::to_string(obj).expect("object to be serializable as JCS")
}
