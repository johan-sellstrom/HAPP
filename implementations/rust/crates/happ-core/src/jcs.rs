\
use serde_json::Value;
use std::collections::BTreeMap;

/// Canonicalize a serde_json::Value into a deterministic JSON string.
///
/// This is intended to be compatible with RFC 8785 (JCS) for the subset of JSON
/// produced by HAPP schemas (objects, arrays, strings, booleans, null, and integers).
///
/// Notes:
/// - Object keys are sorted lexicographically (Unicode codepoint order).
/// - No insignificant whitespace is emitted.
/// - Numbers are serialized via `serde_json::Number::to_string()`.
pub fn canonicalize(value: &Value) -> String {
    match value {
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {
            serde_json::to_string(value).expect("value to be serializable")
        }
        Value::Array(items) => {
            let mut out = String::from("[");
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&canonicalize(item));
            }
            out.push(']');
            out
        }
        Value::Object(map) => {
            // Rebuild in sorted key order.
            let mut sorted: BTreeMap<&String, &Value> = BTreeMap::new();
            for (k, v) in map.iter() {
                sorted.insert(k, v);
            }

            let mut out = String::from("{");
            for (i, (k, v)) in sorted.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                // Keys must be JSON strings.
                out.push_str(&serde_json::to_string(k).expect("key to be serializable"));
                out.push(':');
                out.push_str(&canonicalize(v));
            }
            out.push('}');
            out
        }
    }
}

/// Convenience: canonicalize any serde-serializable object.
pub fn canonicalize_serde<T: serde::Serialize>(obj: &T) -> String {
    let v = serde_json::to_value(obj).expect("serialize to JSON value");
    canonicalize(&v)
}
