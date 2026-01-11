\
use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;

use happ_core::{hash::intent_hash, hash::presentation_hash, signing_view::SigningView, types::ActionIntent};
use happ_crypto::JwtCodec;
use happ_rp::{ExpectedIdentity, RpPolicy, RpVerifier};

#[derive(Parser, Debug)]
#[command(name = "happ-conformance", version, about = "HAPP conformance runner (vectors + checks)")]
struct Args {
    /// Path to a vectors directory (e.g., test_vectors/v0.3)
    #[arg(long)]
    vectors: PathBuf,

    /// Output markdown summary file
    #[arg(long, default_value = "conformance_summary.md")]
    out: PathBuf,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let intent_path = args.vectors.join("action_intent.sample.json");
    let expected_intent_hash_path = args.vectors.join("expected_intent_hash.txt");
    let expected_presentation_hash_path = args.vectors.join("expected_presentation_hash.txt");

    let intent: ActionIntent =
        serde_json::from_slice(&std::fs::read(&intent_path).with_context(|| format!("read {intent_path:?}"))?)
            .context("parse action intent")?;

    let ih = intent_hash(&intent);
    let ph = presentation_hash(&SigningView::from_intent(&intent));

    let expected_ih = std::fs::read_to_string(&expected_intent_hash_path)
        .with_context(|| format!("read {expected_intent_hash_path:?}"))?
        .trim()
        .to_string();
    let expected_ph = std::fs::read_to_string(&expected_presentation_hash_path)
        .with_context(|| format!("read {expected_presentation_hash_path:?}"))?
        .trim()
        .to_string();

    let mut md = String::new();
    md.push_str("# HAPP Conformance Summary\n\n");
    md.push_str("This report is generated from static test vectors.\n\n");

    // CORE-HASH-01
    let core_hash_ok = ih == expected_ih;
    md.push_str(&format!(
        "- **CORE-HASH-01** intent_hash matches vector: {}\n",
        passfail(core_hash_ok)
    ));

    // CORE-PRES-01
    let pres_ok = ph == expected_ph;
    md.push_str(&format!(
        "- **CORE-PRES-01** presentation_hash matches vector: {}\n",
        passfail(pres_ok)
    ));

    // Optional JWT verify
    let jwt_path = args.vectors.join("consent_credential.sample.jwt");
    if jwt_path.exists() {
        let pub_pem = std::fs::read("examples/keys/provider_rsa_public.pem")
            .context("read examples/keys/provider_rsa_public.pem")?;
        // For vector runs we use HS256 decode? No; assume RS256 using the example key pair.
        let jwt = JwtCodec::decoder_rs256_pem(&pub_pem).context("init jwt codec (decode only)")?;
        let verifier = RpVerifier::new(jwt);

        let token = std::fs::read_to_string(&jwt_path).context("read jwt vector")?;
        let mut policy = RpPolicy::default();
        policy.min_pohp_level = happ_core::PoHpLevel::L1;
        policy.identity_mode = happ_core::types::IdentityMode::None;

        let res = verifier.verify(&intent, token.trim(), &intent.audience.id, &policy, None);
        md.push_str(&format!(
            "- **RP-VER-01** RP verifies sample consent credential: {}\n",
            passfail(res.is_ok())
        ));
    } else {
        md.push_str("- **RP-VER-01** RP verifies sample consent credential: (skipped — no JWT vector)\n");
    }

    std::fs::write(&args.out, md).with_context(|| format!("write {out:?}", out = args.out))?;
    println!("wrote {}", args.out.display());
    Ok(())
}

fn passfail(ok: bool) -> &'static str {
    if ok { "PASS" } else { "FAIL" }
}
