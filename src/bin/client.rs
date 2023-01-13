use acmegen::Claims;
use hmac::{Hmac, Mac};
use jwt::SignWithKey;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::Sha256;
use std::{io, path::PathBuf};

#[derive(Serialize, Deserialize)]
struct Input {
    secret: String,

    #[serde(default)]
    persist: Option<PathBuf>,

    #[serde(flatten)]
    token: Claims,
}

#[derive(Serialize, Deserialize)]
struct Output {
    #[serde(rename = "allowfrom")]
    allow_from: Option<String>,

    fulldomain: String,
    subdomain: String,

    username: String,
    password: String,
}

fn main() {
    let input: Input = serde_json::from_reader(io::stdin()).expect("invalid json input");

    let key: Hmac<Sha256> =
        Hmac::new_from_slice(input.secret.as_bytes()).expect("failed to create HMAC");

    let token_str = input
        .token
        .clone()
        .sign_with_key(&key)
        .expect("failed to sign token");

    let output = Output {
        allow_from: input.token.allowed_origins,
        fulldomain: format!("{}.{}", input.token.subdomain, input.token.domain),
        subdomain: input.token.subdomain,
        username: input.token.username,
        password: token_str,
    };

    serde_json::to_writer(io::stdout(), &output).expect("failed to write to stdout");

    if let Some(path) = input.persist {
        let storage = serde_json::to_string(&json!({ output.fulldomain.clone(): output }))
            .expect("failed to serialize to string");
        std::fs::write(path, storage).expect("failed to write to storage");
    }
}
