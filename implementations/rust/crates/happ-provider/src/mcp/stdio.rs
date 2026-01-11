\
use std::io::{self, BufRead, Write};
use std::sync::Arc;

use serde_json::{json, Value};

use happ_core::types::{ActionIntent, Requirements};

use crate::provider::Provider;

/// MCP JSON-RPC error code used by HAPP to signal URL-mode elicitation required.
/// This matches the pattern described in MCP Elicitation for URL mode.
const URL_ELICITATION_REQUIRED: i64 = -32042;

/// Run a minimal MCP stdio server exposing `aaif.happ.request`.
///
/// This is intentionally minimal: it supports `tools/list`, `tools/call`,
/// and no-op handling for `notifications/elicitation/complete`.
pub fn run_stdio_server(provider: Arc<Provider>, web_base_url: String) -> io::Result<()> {
    // Synchronous line-based stdin reader. Works well for simple MCP hosts/inspectors.
    let stdin = io::stdin();
    let mut stdout = io::stdout();

    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let msg: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                let _ = writeln!(
                    stdout,
                    "{}",
                    json!({
                        "jsonrpc":"2.0",
                        "id": null,
                        "error": { "code": -32700, "message": format!("Parse error: {e}") }
                    })
                    .to_string()
                );
                let _ = stdout.flush();
                continue;
            }
        };

        let id = msg.get("id").cloned().unwrap_or(Value::Null);
        let method = msg.get("method").and_then(|m| m.as_str()).unwrap_or("");

        let response = match method {
            "tools/list" => {
                json!({
                    "jsonrpc":"2.0",
                    "id": id,
                    "result": {
                        "tools": [
                            {
                                "name": "aaif.happ.request",
                                "description": "Request a HAPP consent credential (PoHP + optional identity binding) for an Action Intent.",
                                "inputSchema": {
                                    "type":"object",
                                    "required":["requestId"],
                                    "properties": {
                                        "requestId": { "type":"string" },
                                        "actionIntent": { "type":"object" },
                                        "requirements": { "type":"object" },
                                        "challenge": { "type":"object" },
                                        "challengeId": { "type":"string" }
                                    }
                                }
                            }
                        ]
                    }
                })
            }
            "tools/call" => {
                let params = msg.get("params").cloned().unwrap_or(Value::Null);
                let name = params.get("name").and_then(|v| v.as_str()).unwrap_or("");
                if name != "aaif.happ.request" {
                    json!({
                        "jsonrpc":"2.0",
                        "id": id,
                        "error": { "code": -32601, "message": "Unknown tool" }
                    })
                } else {
                    match handle_happ_request(provider.clone(), &web_base_url, &params) {
                        Ok(result) => json!({
                            "jsonrpc":"2.0",
                            "id": id,
                            "result": result
                        }),
                        Err(err) => {
                            // HAPP uses URL-mode elicitation required error for pending sessions.
                            if err.code == URL_ELICITATION_REQUIRED {
                                json!({
                                    "jsonrpc":"2.0",
                                    "id": id,
                                    "error": {
                                        "code": URL_ELICITATION_REQUIRED,
                                        "message": err.message,
                                        "data": err.data
                                    }
                                })
                            } else {
                                json!({
                                    "jsonrpc":"2.0",
                                    "id": id,
                                    "error": { "code": -32000, "message": err.message, "data": err.data }
                                })
                            }
                        }
                    }
                }
            }
            "notifications/elicitation/complete" => {
                // no-op in this reference: the web UI flips the session state.
                json!({
                    "jsonrpc":"2.0",
                    "result": { "ok": true }
                })
            }
            _ => json!({
                "jsonrpc":"2.0",
                "id": id,
                "error": { "code": -32601, "message": "Method not found" }
            }),
        };

        writeln!(stdout, "{}", response.to_string())?;
        stdout.flush()?;
    }

    Ok(())
}

#[derive(Debug)]
struct ToolError {
    code: i64,
    message: String,
    data: Value,
}

fn handle_happ_request(provider: Arc<Provider>, web_base_url: &str, params: &Value) -> Result<Value, ToolError> {
    let args = params.get("arguments").cloned().unwrap_or(Value::Null);

    let request_id = args
        .get("requestId")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ToolError {
            code: -32602,
            message: "Missing requestId".to_string(),
            data: json!({}),
        })?
        .to_string();

    \
    // Accept either explicit actionIntent+requirements OR a single `challenge` object.
    let mut challenge_id: Option<String> = args.get("challengeId").and_then(|v| v.as_str()).map(|s| s.to_string());

    let (action_intent, requirements) = if let Some(ch) = args.get("challenge") {
        let challenge: happ_core::types::HappChallenge = serde_json::from_value(ch.clone()).map_err(|e| ToolError {
            code: -32602,
            message: format!("Invalid challenge: {e}"),
            data: json!({}),
        })?;

        // Basic expiry validation (challenge mode)
        let now = chrono::Utc::now();
        if challenge.expires_at <= now {
            return Err(ToolError {
                code: -32000,
                message: "Challenge expired".to_string(),
                data: json!({ "challengeId": challenge.challenge_id }),
            });
        }

        if challenge_id.is_none() {
            challenge_id = Some(challenge.challenge_id.clone());
        }

        (challenge.action_intent, challenge.requirements)
    } else {
        let action_intent: ActionIntent = serde_json::from_value(
            args.get("actionIntent")
                .cloned()
                .ok_or_else(|| ToolError {
                    code: -32602,
                    message: "Missing actionIntent".to_string(),
                    data: json!({}),
                })?,
        )
        .map_err(|e| ToolError {
            code: -32602,
            message: format!("Invalid actionIntent: {e}"),
            data: json!({}),
        })?;

        let requirements: Requirements = serde_json::from_value(
            args.get("requirements")
                .cloned()
                .ok_or_else(|| ToolError {
                    code: -32602,
                    message: "Missing requirements".to_string(),
                    data: json!({}),
                })?,
        )
        .map_err(|e| ToolError {
            code: -32602,
            message: format!("Invalid requirements: {e}"),
            data: json!({}),
        })?;

        (action_intent, requirements)
    };

    // Audience binding: use the relying party id in the intent.
    let aud = action_intent.audience.id.clone();

    let sid = provider
        .ensure_session(&request_id, &aud, action_intent, requirements, challenge_id)
        .map_err(|e| ToolError {
            code: -32000,
            message: e.to_string(),
            data: json!({}),
        })?;

    let session = provider.get_session(&sid).ok_or_else(|| ToolError {
        code: -32000,
        message: "session missing after creation".to_string(),
        data: json!({}),
    })?;

    match session.status {
        crate::provider::SessionStatus::Approved => {
            let env = provider.issue_credential(&sid).map_err(|e| ToolError {
                code: -32000,
                message: e.to_string(),
                data: json!({}),
            })?;

            Ok(json!({
                "content": [
                    { "type": "text", "text": "Consent credential issued." }
                ],
                "structuredContent": serde_json::to_value(env).unwrap(),
                "isError": false
            }))
        }
        crate::provider::SessionStatus::Denied => Err(ToolError {
            code: -32000,
            message: "User denied".to_string(),
            data: json!({ "sessionId": sid }),
        }),
        crate::provider::SessionStatus::Pending => {
            let url = format!(
                "{}/session/{}",
                web_base_url.trim_end_matches('/'),
                sid
            );
            Err(ToolError {
                code: URL_ELICITATION_REQUIRED,
                message: "User interaction required.".to_string(),
                data: json!({
                    "elicitations": [
                        {
                            "mode": "url",
                            "elicitationId": sid,
                            "url": url,
                            "message": "Verify your presence and approve the requested action."
                        }
                    ]
                }),
            })
        }
    }
}
