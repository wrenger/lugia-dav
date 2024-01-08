use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use clap::Parser;
use dav_server::warp::dav_dir;
use futures_util::TryFutureExt;
use log::error;
use sha2::{Digest, Sha256};
use warp::http::StatusCode;
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
            .map(|_, dav| www_auth(dav))
            .recover(|e| handle_rejection(e).map_ok(www_auth)),
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
            if valid(&salt, &hash, &auth.0).is_ok() {
                Ok(())
            } else {
                Err(reject::custom(AuthError))
            }
        }
    })
}

fn valid(salt: &[u8], hash: &[u8], userpass: &str) -> Result<(), AuthError> {
    let mut hasher = Sha256::new();
    hasher.update(salt);
    hasher.update(userpass);
    let new = hasher.finalize();

    if hash == new.as_slice() {
        Ok(())
    } else {
        Err(AuthError)
    }
}

#[derive(Debug, Clone)]
struct BasicAuth(String);

impl FromStr for BasicAuth {
    type Err = AuthError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.strip_prefix("Basic ").ok_or(AuthError)?;
        let decode = BASE64.decode(s).map_err(|_| AuthError)?;
        let userpass = String::from_utf8(decode).map_err(|_| AuthError)?;
        Ok(BasicAuth(userpass))
    }
}

#[derive(Debug)]
struct AuthError;

impl reject::Reject for AuthError {}

fn www_auth<T: Reply>(r: T) -> WithHeader<T> {
    warp::reply::with_header(
        r,
        "WWW-Authenticate",
        "Basic realm=\"WebDav\", charset=\"UTF-8\"",
    )
}

async fn handle_rejection(err: Rejection) -> Result<impl Reply, Infallible> {
    let unauthorized = || warp::reply::with_status("Unauthorized", StatusCode::UNAUTHORIZED);

    if err.is_not_found() {
        return Ok(warp::reply::with_status("Not Found", StatusCode::NOT_FOUND));
    } else if let Some(h) = err.find::<MissingHeader>() {
        if h.name() == "Authorization" {
            return Ok(unauthorized());
        }
    } else if let Some(h) = err.find::<InvalidHeader>() {
        if h.name() == "Authorization" {
            return Ok(unauthorized());
        }
    } else if err.find::<AuthError>().is_some() {
        return Ok(unauthorized());
    }

    error!("unhandled rejection: {err:?}");
    Ok(warp::reply::with_status(
        "Internal Server Error",
        StatusCode::INTERNAL_SERVER_ERROR,
    ))
}
