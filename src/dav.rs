use std::fs::{File, Metadata};
use std::io::SeekFrom;
use std::io::{self, Seek, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

use chrono::{DateTime, Utc};
use log::{error, info, warn};
use serde::{Deserialize, Serialize, Serializer};
use std::fs::DirEntry;
use tiny_http::{Header, HeaderField, Method, Request, Response, ResponseBox, StatusCode};
use url::Url;

use crate::status;

const MAX_FILE_SIZE: usize = 1 << 30; // 1GiB

#[derive(Debug)]
pub enum Error {
    XML,
    NotImplemented,
    Internal,
    Status(StatusCode),
    Header(&'static str),
    Io(io::Error),
}

#[derive(Clone, Copy)]
pub struct HeaderValue(&'static str);
impl PartialEq<HeaderField> for HeaderValue {
    fn eq(&self, other: &HeaderField) -> bool {
        other.equiv(self.0)
    }
}
impl PartialEq<HeaderValue> for HeaderField {
    fn eq(&self, other: &HeaderValue) -> bool {
        self.equiv(other.0)
    }
}
impl PartialEq<str> for HeaderValue {
    fn eq(&self, other: &str) -> bool {
        self.0.eq_ignore_ascii_case(other)
    }
}
impl PartialEq<HeaderValue> for str {
    fn eq(&self, other: &HeaderValue) -> bool {
        self.eq_ignore_ascii_case(other.0)
    }
}

pub const ALLOW: HeaderValue = HeaderValue("allow");
pub const DEPTH: HeaderValue = HeaderValue("depth");
pub const OVERWRITE: HeaderValue = HeaderValue("overwrite");
pub const DESTINATION: HeaderValue = HeaderValue("destination");
pub const UPDATE_RANGE: HeaderValue = HeaderValue("x-update-range");
pub const CONTENT_TYPE: HeaderValue = HeaderValue("content-type");
pub const LITMUS: HeaderValue = HeaderValue("x-litmus");

impl Error {
    fn not_found() -> Self {
        Self::Io(io::Error::from(io::ErrorKind::NotFound))
    }
}
impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}
impl From<quick_xml::DeError> for Error {
    fn from(e: quick_xml::DeError) -> Self {
        error!("Parse: {e:?}");
        Self::XML
    }
}
impl From<StatusCode> for Error {
    fn from(s: StatusCode) -> Self {
        Self::Status(s)
    }
}

pub struct WebDav {
    dir: PathBuf,
}
impl WebDav {
    pub fn new(dir: PathBuf) -> Arc<Self> {
        Arc::new(Self { dir })
    }

    pub fn handle(&self, rq: &mut Request) -> Result<ResponseBox, Error> {
        info!(
            "{rq:?}\n{:?}",
            rq.headers()
                .iter()
                .map(|h| h.to_string())
                .collect::<Vec<_>>()
        );

        let path = rq.url().strip_prefix('/').unwrap_or(rq.url());
        let path = self.dir.join(path);

        // Some operations can be executed on the root
        let valid_root =
            matches!(rq.method().as_str(), "GET" | "PROPFIND" | "PROPPATCH") && path == self.dir;

        // Ensure that the path is within the directory
        if !valid_root {
            let parent = match path.parent().ok_or(status::FORBIDDEN)?.canonicalize() {
                Ok(parent) => parent,
                Err(e) => {
                    if rq.method().as_str() == "MKCOL" {
                        // MKCOL with missing parent is a conflict
                        return Err(status::CONFLICT.into());
                    }
                    return Err(e.into());
                }
            };
            // Prevent directory traversal
            if !parent.starts_with(&self.dir) {
                return Err(status::FORBIDDEN.into());
            }
        }

        let reader = rq.as_reader();
        let mut body = Vec::new();
        loop {
            let mut buffer = vec![0; 4096];
            let len = reader.read(&mut buffer)?;
            if len == 0 {
                break;
            } else if (body.len() + len) > MAX_FILE_SIZE {
                return Err(status::BAD_REQUEST.into());
            }
            body.extend(&buffer[0..len]);
        }

        match rq.method().as_str() {
            "PROPFIND" | "PROPPATCH" => info!("- {:?}", String::from_utf8(body.clone())),
            _ => {}
        }

        // Ensure that the body is not empty for methods that require it
        if body.len() != 0 {
            let no_body = match rq.method() {
                Method::Get | Method::Head | Method::Options | Method::Delete => true,
                _ => match rq.method().as_str() {
                    "MKCOL" | "COPY" | "MOVE" | "UNLOCK" => true,
                    _ => false,
                },
            };
            if no_body {
                return Err(status::UNSUPPORTED_MEDIA_TYPE.into());
            }
        }

        let headers = rq.headers();
        match rq.method() {
            Method::Get => self.get(false, path),
            Method::Head => self.get(true, path),
            Method::Put => self.put(path, body),
            Method::Patch => self.patch(path, headers, body),
            Method::Options => self.options(path),
            Method::Delete => self.delete(path),
            m => match m.as_str() {
                "PROPFIND" => self.propfind(path, headers, body),
                "PROPPATCH" => self.proppatch(path, headers, body),
                "MKCOL" => self.mkcol(path),
                "COPY" => self.copy(path, headers),
                "MOVE" => self.move_(path, headers),
                "LOCK" => self.lock(path),
                "UNLOCK" => self.unlock(path),
                _ => Err(Error::NotImplemented),
            },
        }
    }

    fn get(&self, head: bool, path: PathBuf) -> Result<ResponseBox, Error> {
        if path.is_dir() {
            use std::fmt::Write;

            let relpath = path.strip_prefix(&self.dir).map_err(|_| Error::Internal)?;

            let mut out = format!(
                "<!DOCTYPE html><head><title>/{}</title></head>\
                <body><table><tr><th>Name</th><th>Type</th><th>Size</th><tr>",
                relpath.display()
            );

            let mut dir = std::fs::read_dir(path)?;
            while let Some(entry) = dir.next().transpose()? {
                let meta = entry.metadata()?;
                let file_type = entry.file_type()?;
                let kind = if file_type.is_file() {
                    "file"
                } else if file_type.is_dir() {
                    "dir"
                } else if file_type.is_symlink() {
                    "symlink"
                } else {
                    "unknown"
                };
                let str_escaped = entry
                    .path()
                    .strip_prefix(&self.dir)
                    .map_err(|_| Error::Internal)?
                    .to_string_lossy()
                    .escape_default()
                    .collect::<String>();
                let html_escaped = entry
                    .file_name()
                    .to_string_lossy()
                    .replace('<', "&lt;")
                    .replace('>', "&gt;");
                writeln!(
                    out,
                    "<tr><td><a href=\"/{str_escaped}\">{html_escaped}</a></td>\
                    <td>{kind}</td><td>{}</td>",
                    meta.len()
                )
                .unwrap();
            }
            writeln!(out, "</body>").unwrap();
            Ok(Response::from_string(out)
                .with_header(
                    Header::from_bytes(CONTENT_TYPE.0, b"text/html; charset=utf-8").unwrap(),
                )
                .boxed())
        } else if path.is_file() {
            let mut res = if head {
                Response::empty(status::OK).boxed()
            } else {
                Response::from_file(File::open(&path)?).boxed()
            };
            res.add_header(
                Header::from_bytes(
                    CONTENT_TYPE.0,
                    mime_guess::from_path(&path).first_or_text_plain().as_ref(),
                )
                .unwrap(),
            );

            // TODO: etag and caching
            Ok(res)
        } else {
            Err(Error::not_found())
        }
    }

    fn put(&self, path: PathBuf, body: Vec<u8>) -> Result<ResponseBox, Error> {
        let mut file = std::fs::File::create(&path)?;
        file.write(&body)?;
        Ok(Response::empty(status::CREATED).boxed())
    }

    fn patch(
        &self,
        path: PathBuf,
        headers: &[Header],
        body: Vec<u8>,
    ) -> Result<ResponseBox, Error> {
        let meta = std::fs::metadata(&path)?;
        let offset = if let Some(offset) = headers.iter().find(|h| h.field == UPDATE_RANGE) {
            let value = offset.value.as_str();
            if value == "append" {
                None
            } else {
                let (start, end) =
                    byte_range(value, meta.len()).ok_or(Error::Header(UPDATE_RANGE.0))?;
                assert!(end + 1 - start == body.len() as u64);
                Some(start)
            }
        } else {
            None
        };

        let mut file = match offset {
            Some(offset) if offset < meta.len() => {
                let mut file = std::fs::OpenOptions::new().write(true).open(&path)?;
                file.seek(SeekFrom::Start(offset))?;
                file
            }
            Some(_) => return Err(Error::not_found()),
            None => std::fs::OpenOptions::new().append(true).open(&path)?,
        };
        file.write_all(&body)?;
        Ok(Response::empty(status::NO_CONTENT).boxed())
    }

    fn options(&self, _path: PathBuf) -> Result<ResponseBox, Error> {
        Ok(Response::empty(status::OK)
            .with_header(
                Header::from_bytes(
                    ALLOW.0,
                    b"GET,HEAD,PUT,OPTIONS,DELETE,PATCH,PROPFIND,COPY,MOVE",
                )
                .unwrap(),
            )
            // TODO: v2 and v3 after locking
            .with_header(Header::from_bytes(b"DAV", b"1").unwrap())
            .boxed())
    }

    fn delete(&self, path: PathBuf) -> Result<ResponseBox, Error> {
        let meta = std::fs::metadata(&path)?;
        if meta.is_file() {
            std::fs::remove_file(&path)?;
        } else if meta.is_dir() {
            std::fs::remove_dir_all(&path)?;
        } else {
            return Err(Error::not_found());
        }
        Ok(Response::empty(status::NO_CONTENT).boxed())
    }

    fn propfind(
        &self,
        path: PathBuf,
        headers: &[Header],
        body: Vec<u8>,
    ) -> Result<ResponseBox, Error> {
        let mut out = MultiStatus::new();

        let _propfind = if !body.is_empty() {
            let body = String::from_utf8(body).map_err(|_| Error::XML)?;
            info!("propfind: {body:?}");
            quick_xml::de::from_str(&body)?
        } else {
            PropFind::default()
        };

        let meta = std::fs::metadata(&path)?;
        if meta.is_dir() {
            let depth: usize = if let Some(depth) = headers.iter().find(|h| h.field == DEPTH) {
                depth
                    .value
                    .as_str()
                    .parse()
                    .map_err(|_| Error::Header(DEPTH.0))?
            } else {
                1
            };

            if depth == 0 {
                out.response
                    .push(PropResponse::new(&path, &meta, &self.dir)?)
            } else {
                let mut stream = read_dir_rec(&path, depth)?;
                while let Some(entry) = stream.pop() {
                    out.response.push(PropResponse::new(
                        &entry.path(),
                        &entry.metadata()?,
                        &self.dir,
                    )?);
                }
            }
        } else if meta.is_file() {
            out.response
                .push(PropResponse::new(&path, &meta, &self.dir)?);
        } else {
            // We currently don't support symlinks
            return Err(Error::not_found());
        }
        info!("{out:?}");

        let out = format!(
            "<?xml version=\"1.0\" encoding=\"utf-8\" ?>{}",
            quick_xml::se::to_string(&out)?
        );
        Ok(Response::from_string(out)
            .with_header(
                Header::from_bytes(CONTENT_TYPE.0, b"text/xml; charset=\"utf-8\"").unwrap(),
            )
            .with_status_code(status::MULTI_STATUS)
            .boxed())
    }

    fn proppatch(
        &self,
        _path: PathBuf,
        _headers: &[Header],
        _body: Vec<u8>,
    ) -> Result<ResponseBox, Error> {
        Err(Error::NotImplemented)
    }

    fn mkcol(&self, path: PathBuf) -> Result<ResponseBox, Error> {
        std::fs::create_dir(&path)?;
        Ok(Response::empty(status::CREATED).boxed())
    }

    fn extract_dst(&self, headers: &[Header]) -> Option<PathBuf> {
        let dst = headers.iter().find(|h| h.field == DESTINATION)?;
        let uri = Url::parse(dst.value.as_str()).ok()?;
        let path = uri.path();
        let dst = Path::new(path.strip_prefix('/').unwrap_or(path));

        let dst = self.dir.join(dst);
        let parent = dst.parent()?.canonicalize().ok()?;
        if !parent.starts_with(&self.dir) {
            return None;
        }

        Some(dst.to_owned())
    }

    fn copy(&self, path: PathBuf, headers: &[Header]) -> Result<ResponseBox, Error> {
        let mut dst = self.extract_dst(&headers).ok_or(status::CONFLICT)?;

        let overwrite = headers
            .iter()
            .find(|h| h.field == OVERWRITE)
            .map_or(false, |v| {
                let v = v.value.as_str();
                v.eq_ignore_ascii_case("t") || v == "1"
            });

        // Copy into directory
        if !path.is_dir() && dst.is_dir() {
            dst.push(path.file_name().unwrap());
        }
        // Remove overwritten files
        if dst.exists() {
            if !overwrite {
                return Err(Error::Status(status::PRECONDITION_FAILED));
            } else {
                warn!("overwriting {dst:?}");
                if dst.is_file() {
                    std::fs::remove_file(&dst)?;
                } else if dst.is_dir() {
                    std::fs::remove_dir_all(&dst)?;
                }
            }
        }

        if std::fs::metadata(&path)?.is_dir() {
            copy_dir_all(&path, &dst)?;
        } else {
            let e = std::fs::copy(&path, &dst);
            if let Err(e) = e {
                warn!("{e:?}");
                return Err(e.into());
            }
        }

        if overwrite {
            Ok(Response::empty(status::NO_CONTENT).boxed())
        } else {
            Ok(Response::empty(status::CREATED).boxed())
        }
    }

    fn move_(&self, path: PathBuf, headers: &[Header]) -> Result<ResponseBox, Error> {
        let mut dst = self
            .extract_dst(&headers)
            .ok_or(Error::Header(DESTINATION.0))?;

        let overwrite = headers
            .iter()
            .find(|h| h.field == OVERWRITE)
            .map_or(false, |v| {
                let v = v.value.as_str();
                v.eq_ignore_ascii_case("t") || v == "1"
            });

        // Move into directory
        if !path.is_dir() && dst.is_dir() {
            dst.push(path.file_name().unwrap());
        }
        // Remove overwritten files
        if dst.exists() {
            if !overwrite {
                return Err(Error::Status(status::PRECONDITION_FAILED));
            } else {
                warn!("overwriting {:?}", dst);
                if dst.is_file() {
                    std::fs::remove_file(&dst)?;
                } else if dst.is_dir() {
                    std::fs::remove_dir_all(&dst)?;
                }
            }
        }

        std::fs::rename(&path, &dst)?;

        if overwrite {
            Ok(Response::empty(status::NO_CONTENT).boxed())
        } else {
            Ok(Response::empty(status::CREATED).boxed())
        }
    }

    fn lock(&self, _path: PathBuf) -> Result<ResponseBox, Error> {
        Err(Error::NotImplemented)

        // if !path.exists() {
        //     return Err(Error::not_found());
        // }

        // // just faking it for now
        // let token = format!("opaquelocktoken:{}", Uuid::new_v4());

        // let mut res = Response::from_string(format!(
        //     "<?xml version=\"1.0\" encoding=\"utf-8\"?>\
        //         <D:prop xmlns:D=\"DAV:\"><D:lockdiscovery><D:activelock>\
        //         <D:locktoken><D:href>{token}</D:href></D:locktoken>\
        //         <D:lockroot><D:href>{}</D:href></D:lockroot>\
        //         </D:activelock></D:lockdiscovery></D:prop>",
        //     path.strip_prefix(&self.dir).unwrap().display()
        // ));

        // res.add_header(
        //     Header::from_bytes(b"content-type", b"application/xml; charset=utf-8").unwrap(),
        // );
        // res.add_header(Header::from_bytes(b"lock-token", format!("<{token}>")).unwrap());
        // Ok(res.boxed())
    }

    fn unlock(&self, _path: PathBuf) -> Result<ResponseBox, Error> {
        Err(Error::NotImplemented)

        // if !path.exists() {
        //     return Err(Error::not_found());
        // }
        // // Not implemented
        // // just faking it for now
        // Ok(Response::empty(status::NO_CONTENT).boxed())
    }
}

fn read_dir_rec(path: &Path, depth: usize) -> Result<Vec<DirEntry>, io::Error> {
    let mut dirs = vec![std::fs::read_dir(path)?];
    let mut res = Vec::new();
    loop {
        let entry = loop {
            if let Some(dir) = dirs.last_mut() {
                if let Some(entry) = dir.next().transpose()? {
                    break entry;
                } else {
                    dirs.pop();
                }
            } else {
                return Ok(res);
            }
        };

        if depth > dirs.len() && entry.metadata()?.is_dir() {
            dirs.push(std::fs::read_dir(entry.path())?);
        }
        res.push(entry);
    }
}

fn copy_dir_all(src: impl AsRef<Path>, dst: impl AsRef<Path>) -> io::Result<()> {
    std::fs::create_dir(&dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        if ty.is_dir() {
            copy_dir_all(entry.path(), dst.as_ref().join(entry.file_name()))?;
        } else {
            std::fs::copy(entry.path(), dst.as_ref().join(entry.file_name()))?;
        }
    }
    Ok(())
}

fn byte_range(range: &str, len: u64) -> Option<(u64, u64)> {
    let (start, end) = range.strip_prefix("bytes=")?.split_once('-')?;
    if start.is_empty() {
        let end: u64 = end.parse().ok()?;
        let start = len.checked_sub(end)?;
        Some((start, len - 1))
    } else {
        let start = start.parse().ok()?;
        let end = if end.is_empty() {
            len - 1
        } else {
            end.parse().ok()?
        };
        (start <= end && end < len).then_some((start, end))
    }
}

#[derive(Deserialize, Serialize, Debug, Default)]
#[serde(rename = "propfind")]
struct PropFind {
    #[serde(rename = "$value")]
    propfind: PropFindInner,
}

#[derive(Deserialize, Serialize, Debug, Default)]
#[serde(rename_all = "lowercase")]
enum PropFindInner {
    Prop {
        #[serde(rename = "$value")]
        props: Vec<PropFindKind>,
    },
    #[default]
    AllProp,
}

#[derive(Deserialize, Serialize, Debug)]
#[serde(rename_all = "lowercase")]
enum PropFindKind {
    DisplayName,
    RessourceType,
    GetContentLength,
    GetLastModified,
    #[serde(other, skip_serializing)]
    Other,
}

#[derive(Serialize, Debug)]
#[serde(rename = "multistatus")]
struct MultiStatus {
    #[serde(rename = "@xmlns", serialize_with = "MultiStatus::dav_ns")]
    xmlns: (),
    response: Vec<PropResponse>,
}
impl MultiStatus {
    fn new() -> Self {
        Self {
            xmlns: (),
            response: Vec::new(),
        }
    }
    fn dav_ns<S: Serializer>(_: &(), se: S) -> Result<S::Ok, S::Error> {
        se.serialize_str("DAV:")
    }
}

#[derive(Serialize, Debug)]
struct PropResponse {
    href: String,
    propstat: PropStat,
}

#[derive(Serialize, Debug)]
struct PropStat {
    prop: Prop,
    #[serde(serialize_with = "PropStat::status_code")]
    status: StatusCode,
}
impl PropStat {
    fn status_code<S: Serializer>(s: &StatusCode, se: S) -> Result<S::Ok, S::Error> {
        se.serialize_str(&format!("HTTP/1.1 {} {}", s.0, s.default_reason_phrase()))
    }
}

#[derive(Serialize, Debug)]
#[serde(rename = "prop")]
struct Prop {
    #[serde(rename = "$value")]
    prop: Vec<PropKind>,
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "lowercase")]
enum PropKind {
    CreationDate(String),
    DisplayName(String),
    GetContentLength(u64),
    GetContentType(String),
    GetLastModified(String),
    ResourceType(Option<PropCollection>),
}

#[derive(Serialize, Debug)]
struct PropCollection {
    collection: (),
}

impl PropResponse {
    fn new(path: &Path, meta: &Metadata, base: &Path) -> Result<Self, Error> {
        Ok(Self {
            href: normalize_path(path.strip_prefix(base).map_err(|_| Error::not_found())?),
            propstat: PropStat {
                prop: Prop {
                    prop: vec![
                        PropKind::CreationDate(date_str(meta.created()?)),
                        PropKind::DisplayName(
                            path.file_name()
                                .and_then(|n| n.to_str())
                                .unwrap_or_default()
                                .into(),
                        ),
                        PropKind::GetContentLength(meta.len()),
                        PropKind::GetContentType(
                            mime_guess::from_path(&path)
                                .first_or_text_plain()
                                .as_ref()
                                .into(),
                        ),
                        PropKind::ResourceType(
                            meta.is_dir().then_some(PropCollection { collection: () }),
                        ),
                        PropKind::GetLastModified(date_str(meta.modified()?)),
                    ],
                },
                status: status::OK,
            },
        })
    }
}

fn normalize_path(path: &Path) -> String {
    let path = format!("/{}", path.to_str().unwrap_or_default());
    if cfg!(windows) {
        path.replace('\\', "/")
    } else {
        path
    }
}

fn date_str(time: SystemTime) -> String {
    DateTime::<Utc>::from(time).to_rfc3339()
}

#[cfg(test)]
mod test {
    use chrono::DateTime;
    use std::path::Path;

    use crate::dav::PropFind;

    use super::{byte_range, PropResponse};

    #[test]
    fn parse_range() {
        assert_eq!(byte_range("bytes=0-499", 500), Some((0, 499)));
        assert_eq!(byte_range("bytes=0-", 500), Some((0, 499)));
        assert_eq!(byte_range("bytes=299-", 500), Some((299, 499)));
        assert_eq!(byte_range("bytes=-500", 500), Some((0, 499)));
        assert_eq!(byte_range("bytes=-300", 500), Some((200, 499)));
        assert_eq!(byte_range("bytes=500-", 500), None);
        assert_eq!(byte_range("bytes=-501", 500), None);
        assert_eq!(byte_range("bytes=0-500", 500), None);
    }

    #[test]
    fn prop_response() {
        let path = Path::new("src/");
        let base = Path::new("");
        let meta = path.metadata().unwrap();
        let res = PropResponse::new(path, &meta, base).unwrap();
        let xml = quick_xml::se::to_string(&res).unwrap();
        println!("{res:?}");
        println!("{xml}");

        let mtime = meta
            .modified()
            .unwrap()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mtime = DateTime::from_timestamp(mtime as _, 0).unwrap();

        assert_eq!(
            xml,
            format!(
                "<PropResponse><href>/src</href><propstat><prop>\
                <displayname>src</displayname>\
                <resourcetype><collection/></resourcetype>\
                <getcontentlength>{}</getcontentlength>\
                <getlastmodified>{}</getlastmodified>\
                </prop><status>HTTP/1.1 200 OK</status></propstat></PropResponse>",
                meta.len(),
                mtime.to_rfc3339()
            )
        );
    }

    #[test]
    fn propfind() {
        let xml = r#"<?xml version="1.0" encoding="utf-8"?>
            <propfind xmlns="DAV:"><prop>
            <getcontentlength xmlns="DAV:"/>
            <getlastmodified xmlns="DAV:"/>
            <displayname xmlns="DAV:"/>
            <resourcetype xmlns="DAV:"/>
            <foo xmlns="http://example.com/neon/litmus/"/>
            <bar xmlns="http://example.com/neon/litmus/"/>
            </prop></propfind>"#;

        let propfind: PropFind = quick_xml::de::from_str(xml).unwrap();
        println!("{propfind:?}");
    }
}
