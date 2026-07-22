use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, available_parallelism};

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use clap::Parser;
use log::{info, trace};
use sha2::{Digest, Sha256};
use tiny_http::{Header, Request, Response, Server, SslConfig};

mod dav;
mod multi_status;
mod util;

mod status {
    use tiny_http::StatusCode;

    pub const OK: StatusCode = StatusCode(200);
    pub const CREATED: StatusCode = StatusCode(201);
    pub const NO_CONTENT: StatusCode = StatusCode(204);
    pub const MULTI_STATUS: StatusCode = StatusCode(207);

    pub const BAD_REQUEST: StatusCode = StatusCode(400);
    pub const UNAUTHORIZED: StatusCode = StatusCode(401);
    pub const FORBIDDEN: StatusCode = StatusCode(403);
    pub const NOT_FOUND: StatusCode = StatusCode(404);
    pub const METHOD_NOT_ALLOWED: StatusCode = StatusCode(405);
    pub const CONFLICT: StatusCode = StatusCode(409);
    pub const PRECONDITION_FAILED: StatusCode = StatusCode(412);
    pub const UNSUPPORTED_MEDIA_TYPE: StatusCode = StatusCode(415);

    pub const INTERNAL_SERVER_ERROR: StatusCode = StatusCode(500);
    pub const NOT_IMPLEMENTED: StatusCode = StatusCode(501);
}

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

fn main() {
    env_logger::init();

    let Args {
        dir,
        host,
        key,
        cert,
        login,
    } = Args::parse();

    let dir = dir.canonicalize().expect("invalid dir");

    info!("listening on {host:?} serving {dir:?}");

    let (salt, hash) = login.split_once(':').expect("invalid login config");
    let salt = hex::decode(salt).expect("invalid login config");
    let hash = hex::decode(hash).expect("invalid login config");

    let ssl = SslConfig {
        certificate: fs::read(cert).expect("no ssl certificate"),
        private_key: fs::read(key).expect("no ssl private key"),
    };

    let server = tiny_http::Server::https(host, ssl).expect("invalid host or ssl");
    let running = AtomicBool::new(true);
    start(&server, |rq| authenticate(rq, &salt, &hash), &dir, &running);
}

fn start(
    server: &Server,
    authenticate: impl Fn(Request) -> Option<Request> + Send + Sync,
    dir: &Path,
    running: &AtomicBool,
) {
    thread::scope(|s| {
        let threads = available_parallelism().unwrap().get();
        let mut guards = Vec::with_capacity(threads);
        for _ in 0..threads {
            let guard = s.spawn(|| {
                for rq in server.incoming_requests() {
                    if let Some(mut rq) = authenticate(rq) {
                        let _ = match dav::handle(dir, &mut rq) {
                            Ok(res) => rq.respond(res),
                            Err(e) => {
                                let res = e.response(&rq);
                                rq.respond(res)
                            }
                        };
                    }
                    if !running.load(Ordering::Relaxed) {
                        break;
                    }
                }
            });

            guards.push(guard);
        }
    })
}

fn authenticate(rq: Request, salt: &[u8], hash: &[u8]) -> Option<Request> {
    let authorized = rq.headers().iter().any(|h| {
        h.field.as_str() == "Authorization"
            && BasicAuth::from_str(h.value.as_str())
                .map(|b| valid(salt, hash, &b.0))
                .unwrap_or_default()
    });
    if !authorized {
        trace!("invalid login attempt {rq:?}");

        let res = Response::empty(status::UNAUTHORIZED).with_header(
            Header::from_bytes(
                b"WWW-Authenticate",
                b"Basic realm=\"WebDav\", charset=\"UTF-8\"",
            )
            .unwrap(),
        );
        let _ = rq.respond(res);
        return None;
    }
    Some(rq)
}

fn valid(salt: &[u8], hash: &[u8], userpass: &str) -> bool {
    let mut hasher = Sha256::new();
    hasher.update(salt);
    hasher.update(userpass);
    let new = hasher.finalize();

    hash == new.as_slice()
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

#[cfg(test)]
mod test {
    use std::fs::create_dir_all;
    use std::net::Ipv4Addr;
    use std::path::Path;
    use std::process::Command;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::thread;

    use log::info;
    use tiny_http::Server;

    use crate::start;

    #[test]
    fn litmus() {
        let _ = env_logger::builder().is_test(true).try_init();
        info!("start");

        let dir = Path::new("tmp");
        create_dir_all(dir).unwrap();

        let litmus_dir = Path::new("litmus");
        create_dir_all(litmus_dir).unwrap();

        let server = Server::http((Ipv4Addr::new(127, 0, 0, 1), 4918)).unwrap();

        let running = AtomicBool::new(true);
        thread::scope(|s| {
            let handle = s.spawn(|| start(&server, Some, dir, &running));

            let status = Command::new("litmus")
                .current_dir(litmus_dir)
                .env("TESTS", "http basic copymove locks props")
                .arg("http://localhost:4918/")
                .arg("someuser")
                .arg("somepass")
                .status()
                .expect("litmus failed");

            if !status.success() {
                log::warn!("Localfs might not complete litmus");
            }

            running.store(false, Ordering::Relaxed);

            while !handle.is_finished() {
                server.unblock();
            }
            handle.join().unwrap();

            std::fs::remove_dir_all("tmp").unwrap();
        })
    }
}
