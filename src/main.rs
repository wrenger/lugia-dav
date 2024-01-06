use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use clap::Parser;
use dav_server::warp::dav_dir;
use log::error;
use sha2::{Digest, Sha256};
use warp::reject::{self, InvalidHeader, MissingHeader, Rejection};
use warp::reply::{Reply, WithHeader};
use warp::Filter;

#[derive(Debug, Parser)]
#[command(author, about, version)]
struct Args {
    host: SocketAddr,
    /// Directory to serve
    #[clap(short, long, required = true)]
    dir: PathBuf,
    /// TLS key
    #[clap(short, long, required = true)]
    key: PathBuf,
    /// TLS certificate
    #[clap(short, long, required = true)]
    cert: PathBuf,
    /// Salt:<hashed username:password>
    #[clap(short, long, required = true)]
    login: String,
}

#[tokio::main]
async fn main() {
    env_logger::init();

    let Args {
        dir,
        host,
        key,
        cert,
        login,
    } = Args::parse();

    println!("warp example: listening on {host:?} serving {dir:?}");

    let dav = dav_dir(dir, false, true);

    let (salt, hash) = login.split_once(':').expect("invalid login config");
    let salt = hex::decode(salt).expect("invalid login config");
    let hash = hex::decode(hash).expect("invalid login config");

    warp::serve(
        warp::any()
            .and(auth(salt, hash))
            .and(dav)
            .map(|_, dav| dav)
            .recover(handle_rejection),
    )
    .tls()
    .cert_path(cert)
    .key_path(key)
    .run(host)
    .await;
}

fn auth(salt: Vec<u8>, hash: Vec<u8>) -> impl Filter<Extract = ((),), Error = Rejection> + Clone {
    let salt = salt.leak();
    let hash = hash.leak();
    warp::header::<BasicAuth>("Authorization").and_then(|auth: BasicAuth| {
        let salt = salt.to_owned();
        let hash = hash.to_owned();
        async move {
            if valid(&salt, &hash, &auth.userpass).is_ok() {
                Ok(())
            } else {
                Err(reject::custom(AuthError))
            }
        }
    })
}

fn valid(salt: &[u8], hash: &[u8], auth: &str) -> Result<(), AuthError> {
    let mut hasher = Sha256::new();
    hasher.update(salt);
    hasher.update(auth);
    let new = hasher.finalize();

    if hash == new.as_slice() {
        Ok(())
    } else {
        Err(AuthError)
    }
}

#[derive(Debug)]
struct AuthError;

impl reject::Reject for AuthError {}

#[derive(Debug, Clone)]
struct BasicAuth {
    userpass: String,
}

impl FromStr for BasicAuth {
    type Err = AuthError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.strip_prefix("Basic ").ok_or(AuthError)?;
        let decode = BASE64.decode(s).map_err(|_| AuthError)?;
        let userpass = String::from_utf8(decode).map_err(|_| AuthError)?;
        Ok(BasicAuth { userpass })
    }
}

fn www_auth<T: Reply>(r: T) -> WithHeader<T> {
    warp::reply::with_header(
        r,
        "WWW-Authenticate",
        "Basic realm=\"WebDav\", charset=\"UTF-8\"",
    )
}

async fn handle_rejection(err: Rejection) -> Result<impl Reply, Infallible> {
    Ok(www_auth('out: {
        if err.is_not_found() {
            break 'out warp::reply::with_status("Not Found", warp::http::StatusCode::NOT_FOUND);
        } else if let Some(h) = err.find::<MissingHeader>() {
            if h.name() == "Authorization" {
                break 'out warp::reply::with_status(
                    "Unauthorized",
                    warp::http::StatusCode::UNAUTHORIZED,
                );
            }
        } else if let Some(h) = err.find::<InvalidHeader>() {
            error!("InvalidHeader: {h:?}");
            if h.name() == "Authorization" {
                break 'out warp::reply::with_status(
                    "Unauthorized",
                    warp::http::StatusCode::UNAUTHORIZED,
                );
            }
        } else if let Some(_) = err.find::<AuthError>() {
            break 'out warp::reply::with_status(
                "Unauthorized",
                warp::http::StatusCode::UNAUTHORIZED,
            );
        }

        error!("unhandled rejection: {err:?}");
        warp::reply::with_status(
            "Internal Server Error",
            warp::http::StatusCode::INTERNAL_SERVER_ERROR,
        )
    }))
}
