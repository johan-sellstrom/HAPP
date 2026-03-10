use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::Context;
use clap::{Parser, ValueEnum};
use tracing_subscriber::EnvFilter;

use happ_crypto::{JwtCodec, JwtSigningAlg};
use happ_provider::adapters::{
    entra_mock::EntraMockAdapter,
    entra_oidc_pkce::{EntraOidcConfig, EntraOidcPkceAdapter},
    AdapterRegistry,
};
use happ_provider::{Provider, ProviderConfig};

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
enum RuntimeMode {
    Development,
    Production,
}

#[derive(Parser, Debug)]
#[command(
    name = "happd",
    version,
    about = "HAPP reference provider (MCP stdio + URL UI)"
)]
struct Args {
    /// Runtime hardening mode.
    #[arg(long, value_enum, default_value_t = RuntimeMode::Development)]
    mode: RuntimeMode,

    /// Web UI bind address, e.g. 127.0.0.1:8787
    #[arg(long, default_value = "127.0.0.1:8787")]
    web_addr: SocketAddr,

    /// Base URL for the web UI, e.g. http://127.0.0.1:8787
    /// If omitted, derived from web_addr with http://
    #[arg(long)]
    web_base_url: Option<String>,

    /// Issuer identifier for the consent credential (e.g., did:web:pp.example)
    #[arg(long, default_value = "did:web:provider.example")]
    issuer: String,

    /// RP audience identifier (for demos; normally comes from ActionIntent)
    #[arg(long, default_value = "did:web:rp.example")]
    audience: String,

    /// JWT signing algorithm: RS256 or HS256
    #[arg(long, default_value = "RS256")]
    signing_alg: String,

    /// RSA private key PEM (for RS256)
    #[arg(long)]
    signing_key: Option<PathBuf>,

    /// RSA public key PEM (for RS256). If omitted, derived by replacing _private with _public for demos.
    #[arg(long)]
    public_key: Option<PathBuf>,

    /// HMAC secret (for HS256)
    #[arg(long)]
    hmac_secret: Option<String>,

    /// Default credential TTL (seconds)
    #[arg(long, default_value_t = 120)]
    credential_ttl_seconds: i64,

    /// Provider certification reference URI.
    #[arg(long)]
    provider_cert_ref: Option<String>,

    /// Identity adapter to register: entra_oidc (real if configured, otherwise mock)
    #[arg(long, default_value = "entra_oidc")]
    identity_adapter: String,

    /// Entra tenant (common|organizations|<tenant-id>)
    #[arg(long, default_value = "common")]
    entra_tenant: String,

    /// Entra client id
    #[arg(long)]
    entra_client_id: Option<String>,

    /// Entra client secret (optional for public clients)
    #[arg(long)]
    entra_client_secret: Option<String>,

    /// Shared secret for external PoHP attestation API.
    #[arg(long)]
    pohp_attestation_secret: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let args = Args::parse();
    validate_runtime_args(&args)?;

    let web_base_url = args
        .web_base_url
        .unwrap_or_else(|| format!("http://{}", args.web_addr));

    // Signing setup
    let signing_alg = match args.signing_alg.as_str() {
        "RS256" => JwtSigningAlg::RS256,
        "HS256" => JwtSigningAlg::HS256,
        other => anyhow::bail!("unsupported --signing-alg {other}"),
    };

    let jwt = match signing_alg {
        JwtSigningAlg::RS256 => {
            let priv_path = args
                .signing_key
                .clone()
                .unwrap_or_else(|| PathBuf::from("examples/keys/provider_rsa_private.pem"));
            let pub_path = args
                .public_key
                .clone()
                .unwrap_or_else(|| PathBuf::from("examples/keys/provider_rsa_public.pem"));

            let priv_pem =
                std::fs::read(&priv_path).with_context(|| format!("read {priv_path:?}"))?;
            let pub_pem = std::fs::read(&pub_path).with_context(|| format!("read {pub_path:?}"))?;
            JwtCodec::from_rs256_pem(&priv_pem, &pub_pem).context("init RS256 codec")?
        }
        JwtSigningAlg::HS256 => {
            let secret = args
                .hmac_secret
                .clone()
                .unwrap_or_else(|| "dev-secret-change-me".to_string());
            JwtCodec::from_hs256(secret.as_bytes()).context("init HS256 codec")?
        }
    };

    let provider_cert = happ_core::types::ProviderCertificationRef {
        reference: args
            .provider_cert_ref
            .clone()
            .unwrap_or_else(|| "https://aaif.example/certifications/provider/placeholder".to_string()),
        hash: None,
        embedded: None,
    };

    let cfg = ProviderConfig {
        issuer: args.issuer.clone(),
        provider_cert,
        credential_ttl_seconds: args.credential_ttl_seconds,
    };

    // Register adapters
    let mut reg = AdapterRegistry::new();
    let allow_mock_identity = matches!(args.mode, RuntimeMode::Development);
    let allow_mock_pohp = matches!(args.mode, RuntimeMode::Development);

    if allow_mock_identity {
        reg.register(std::sync::Arc::new(EntraMockAdapter::new()));
    }

    if args.identity_adapter.contains("entra_oidc") {
        if let Some(client_id) = args.entra_client_id.clone() {
            let entra_cfg = EntraOidcConfig {
                tenant: args.entra_tenant.clone(),
                client_id,
                client_secret: args.entra_client_secret.clone(),
                redirect_base: web_base_url.clone(),
            };
            // Overwrite the mock adapter for scheme `entra_oidc`.
            reg.register(std::sync::Arc::new(EntraOidcPkceAdapter::new(entra_cfg)));
        } else {
            tracing::warn!(
                "entra_oidc requested but --entra-client-id not provided; using mock adapter"
            );
        }
    }

    let provider = Provider::new(cfg, jwt, reg);

    // Run web UI and MCP stdio server concurrently.
    let provider_for_mcp = provider.clone();
    let web_base_for_mcp = web_base_url.clone();
    std::thread::spawn(move || {
        // Blocking stdio loop in a dedicated thread.
        let _ = happ_provider::mcp::run_stdio_server(provider_for_mcp, web_base_for_mcp);
    });

    tracing::info!("web UI: {}", web_base_url);
    tracing::info!("MCP stdio: running (connect with your MCP host)");

    // Web server (async)
    happ_provider::web::run_web_server(
        provider,
        args.web_addr,
        web_base_url,
        allow_mock_pohp,
        allow_mock_identity,
        args.pohp_attestation_secret.clone(),
    )
    .await?;

    Ok(())
}

fn validate_runtime_args(args: &Args) -> anyhow::Result<()> {
    if !matches!(args.mode, RuntimeMode::Production) {
        return Ok(());
    }

    if args.signing_alg != "RS256" {
        anyhow::bail!("production mode requires --signing-alg RS256");
    }

    let signing_key = args
        .signing_key
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("production mode requires --signing-key"))?;
    let public_key = args
        .public_key
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("production mode requires --public-key"))?;

    for path in [signing_key, public_key] {
        if path.components().any(|component| component.as_os_str() == "examples") {
            anyhow::bail!("production mode forbids example signing keys: {}", path.display());
        }
    }

    let provider_cert_ref = args
        .provider_cert_ref
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("production mode requires --provider-cert-ref"))?;
    if provider_cert_ref.contains("placeholder") || provider_cert_ref.contains(":demo") {
        anyhow::bail!("production mode requires a real provider certification reference");
    }

    if args.pohp_attestation_secret.as_deref().unwrap_or("").is_empty() {
        anyhow::bail!("production mode requires --pohp-attestation-secret");
    }

    if args.identity_adapter.contains("entra_oidc") && args.entra_client_id.is_none() {
        anyhow::bail!("production mode requires --entra-client-id when using entra_oidc");
    }

    Ok(())
}
