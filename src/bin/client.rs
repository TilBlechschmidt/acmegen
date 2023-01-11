use acmegen::Claims;
use hmac::{Hmac, Mac};
use jwt::SignWithKey;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::io;

#[derive(Serialize, Deserialize)]
struct Input {
    secret: String,

    #[serde(flatten)]
    token: Claims,
}

#[derive(Serialize, Deserialize)]
struct Output {
    #[serde(rename = "allowfrom")]
    allow_from: Vec<String>,

    fulldomain: String,
    subdomain: String,

    username: String,
    password: String,
}

fn main() {
    let input: Input = serde_json::from_reader(io::stdin()).expect("invalid json input");
    let key: Hmac<Sha256> = Hmac::new_from_slice(input.secret.as_bytes()).unwrap();
    let token_str = input.token.clone().sign_with_key(&key).unwrap();

    let output = Output {
        allow_from: input.token.allowed_origins,
        fulldomain: format!("{}.{}", input.token.subdomain, input.token.domain),
        subdomain: input.token.subdomain,
        username: input.token.username,
        password: token_str,
    };

    serde_json::to_writer(io::stdout(), &output).unwrap();
}
