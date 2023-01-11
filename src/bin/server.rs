use acmegen::{parse_seconds, Claims, Record, RecordStore};
use clap::Parser;
use hmac::{Hmac, Mac};
use jwt::VerifyWithKey;
use serde_json::json;
use sha2::Sha256;
use std::{net::SocketAddr, ops::Deref, path::PathBuf, sync::Arc, time::Duration};
use tokio::{
    fs,
    sync::{Mutex, Notify},
    task,
    time::sleep,
};
use warp::{hyper::StatusCode, reply, Filter};

const HEADER_X_API_USER: &str = "X-Api-User";
const HEADER_X_API_KEY: &str = "X-Api-Key";

#[derive(Parser)]
struct Options {
    /// How often to check for and purge stale announcements
    #[clap(long, default_value = "60", value_parser = parse_seconds)]
    purge_interval: Duration,

    /// Time after which a record is considered stale
    #[clap(long, default_value = "600", value_parser = parse_seconds)]
    max_age: Duration,

    /// HTTP port to listen on
    #[clap(long, default_value = "3030")]
    port: u16,

    /// Prints added/removed IPs and domains
    #[clap(short, long)]
    verbose: bool,

    /// JWT secret used to verify tokens
    #[clap(long, env)]
    secret: String,

    /// Domain prefix for which subdomains should be allowed
    domain: String,

    /// Location to store the zone file at
    zone_file: PathBuf,

    /// Where the authoritive nameserver for the given domain can be found
    #[clap(short, long)]
    authoritive_nameserver: String,
}

/// Waits for changes on the given notifier and generates a new config every time it gets notified
async fn config_update_loop(
    store: Arc<Mutex<RecordStore>>,
    notifier: Arc<Notify>,
    domain: String,
    authoritive_nameserver: String,
    path: PathBuf,
) {
    let mut zone_serial = 0;

    loop {
        let bytes = {
            let store = store.lock().await;
            let entries = store.entries();

            // For more details on zone file formatting and what the mandatory SOA entry is all about, see:
            // https://help.dyn.com/how-to-format-a-zone-file/

            let mut zone_file: String = format!(
                "@               3600 SOA {authoritive_nameserver: >16}. zone-admin.{domain}. {zone_serial} 3600 600 604800 1800\n"
            );

            for record in entries {
                let txt_content = format!("\"{}\"", record.txt);
                zone_file += &format!("{: <16} 60 IN TXT {: >16}\n", record.subdomain, txt_content);
            }

            zone_file.into_bytes()
        };

        if let Err(err) = fs::write(&path, bytes).await {
            eprintln!("Failed to write zone file: {err}");
        }

        zone_serial += 1;
        notifier.notified().await;
    }
}

/// Purges old entries every `PURGE_INTERVAL_SEC` and sends notifications if changes have been made
async fn cleanup_loop(store: Arc<Mutex<RecordStore>>, notifier: Arc<Notify>, interval: Duration) {
    loop {
        sleep(interval).await;

        if store.lock().await.purge_old() > 0 {
            notifier.notify_waiters();
        }
    }
}

fn verify_auth(
    record: &Record,
    user: String,
    password: String,
    domain: String,
    origin: Option<SocketAddr>,
    key: Arc<Hmac<Sha256>>,
) -> bool {
    let claims: Result<Claims, _> = password.verify_with_key(key.deref());

    match claims {
        Ok(claims)
            if claims.username == user
                && claims.domain == domain
                && claims.subdomain == record.subdomain =>
        {
            true
        }
        Ok(_) => {
            println!("! Token validation failed for '{}'", record.subdomain);
            false
        }
        Err(_) => {
            println!("! Token verification failed for '{}'", record.subdomain);
            false
        }
    }
}

/// Stores announcements received via HTTP POST in the given store and sends notifications each time it does so
async fn http_server(
    store: Arc<Mutex<RecordStore>>,
    notifier: Arc<Notify>,
    port: u16,
    domain: String,
    key: Arc<Hmac<Sha256>>,
) {
    let store_ref = store.clone();

    let receiver = warp::path("update")
        .and(warp::path::end())
        .and(warp::post())
        .and(warp::body::content_length_limit(8192))
        .and(warp::body::json())
        .and(warp::header(HEADER_X_API_USER))
        .and(warp::header(HEADER_X_API_KEY))
        .and(warp::addr::remote())
        .then(
            move |record: Record, user: String, password: String, origin: Option<SocketAddr>| {
                let store = store_ref.clone();
                let notifier = notifier.clone();
                let domain = domain.clone();
                let key = key.clone();

                async move {
                    if !verify_auth(&record, user, password, domain, origin, key) {
                        warp::reply::with_status(
                            warp::reply::json(&json!({ "error": "401 Unauthorized" })),
                            StatusCode::UNAUTHORIZED,
                        )
                    } else {
                        if store.lock().await.add(record.clone()) {
                            notifier.notify_waiters();
                        }

                        warp::reply::with_status(
                            warp::reply::json(&json!({ "txt": record.txt })),
                            StatusCode::OK,
                        )
                    }
                }
            },
        );

    let query = warp::get().then(move || {
        let store = store.clone();
        async move { reply::json(&store.lock().await.entries()) }
    });

    let routes = query.or(receiver);

    warp::serve(routes).run(([0, 0, 0, 0], port)).await;
}

#[tokio::main]
async fn main() {
    let options = Options::parse();

    let notifier = Arc::new(Notify::new());
    let store = Arc::new(Mutex::new(RecordStore::new(
        options.max_age,
        options.verbose,
    )));

    let key =
        Arc::new(Hmac::new_from_slice(options.secret.as_bytes()).expect("invalid secret data"));

    task::spawn(config_update_loop(
        store.clone(),
        notifier.clone(),
        options.domain.clone(),
        options.authoritive_nameserver,
        options.zone_file,
    ));

    task::spawn(cleanup_loop(
        store.clone(),
        notifier.clone(),
        options.purge_interval,
    ));

    println!(
        "listening on 0.0.0.0:{} (domain=*.{})",
        options.port, options.domain
    );

    http_server(store, notifier, options.port, options.domain, key).await;
}
