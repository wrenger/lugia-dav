use std::fs::{File, Metadata};
use std::io::{self, Seek, Write};
use std::io::{ErrorKind, SeekFrom};
use std::path::{Component, Path, PathBuf};
use std::time::SystemTime;

use chrono::{DateTime, Utc};
use log::{error, info, warn};
use serde::{Deserialize, Serialize, Serializer};
use std::fs::DirEntry;
use tiny_http::{Header, HeaderField, Method, Request, Response, ResponseBox, StatusCode};
use url::Url;

use crate::status;

const MAX_FILE_SIZE: usize = 1 << 30; // 1GiB

pub const ALLOW: HeaderValue = HeaderValue("allow");
pub const DEPTH: HeaderValue = HeaderValue("depth");
pub const OVERWRITE: HeaderValue = HeaderValue("overwrite");
pub const DESTINATION: HeaderValue = HeaderValue("destination");
pub const UPDATE_RANGE: HeaderValue = HeaderValue("x-update-range");
pub const CONTENT_TYPE: HeaderValue = HeaderValue("content-type");
pub const LITMUS: HeaderValue = HeaderValue("x-litmus");

#[derive(Debug)]
pub enum Error {
    Xml,
    NotImplemented,
    Internal,
    Status(StatusCode),
    Header(&'static str),
    Io(io::Error),
}
impl Error {
    pub fn response(self, rq: &Request) -> ResponseBox {
        let is_litmus = rq.headers().iter().any(|h| h.field == LITMUS);

        match self {
            Error::Xml => Response::from_string("XML parsing error")
                .with_status_code(status::BAD_REQUEST)
                .boxed(),

            Error::NotImplemented => Response::empty(status::NOT_IMPLEMENTED).boxed(),
            Error::Internal => Response::empty(status::INTERNAL_SERVER_ERROR).boxed(),
            Error::Status(s) => Response::empty(s).boxed(),
            Error::Header(h) => Response::from_string(format!("Missing header: {h}"))
                .with_status_code(status::BAD_REQUEST)
                .boxed(),

            Error::Io(e) => Response::empty(match e.kind() {
                ErrorKind::NotFound => status::NOT_FOUND,
                ErrorKind::PermissionDenied => status::FORBIDDEN,
                ErrorKind::AlreadyExists if is_litmus => status::METHOD_NOT_ALLOWED,
                // Some clients just love recreating already existing directories
                ErrorKind::AlreadyExists => status::NO_CONTENT,
                ErrorKind::InvalidInput => status::BAD_REQUEST,
                ErrorKind::InvalidData => status::BAD_REQUEST,
                ErrorKind::Unsupported => status::FORBIDDEN,
                ErrorKind::UnexpectedEof => status::INTERNAL_SERVER_ERROR,
                ErrorKind::OutOfMemory => status::INTERNAL_SERVER_ERROR,
                _ => {
                    error!("{e:?}");
                    status::INTERNAL_SERVER_ERROR
                }
            })
            .boxed(),
        }
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
        Self::Xml
    }
}
impl From<StatusCode> for Error {
    fn from(s: StatusCode) -> Self {
        Self::Status(s)
    }
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

pub fn handle(root: &Path, rq: &mut Request) -> Result<ResponseBox, Error> {
    info!(
        "{} {} {:?}",
        rq.method(),
        rq.url(),
        rq.headers()
            .iter()
            .map(|h| h.to_string())
            .collect::<Vec<_>>()
    );

    let relpath = path_normalize(rq.url())?;

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

    // Ensure that the body is not empty for methods that require it
    if !body.is_empty() {
        let no_body = match rq.method() {
            Method::Get | Method::Head | Method::Options | Method::Delete => true,
            _ => matches!(rq.method().as_str(), "MKCOL" | "COPY" | "MOVE" | "UNLOCK"),
        };
        if no_body {
            return Err(status::UNSUPPORTED_MEDIA_TYPE.into());
        }
    }

    match rq.method() {
        Method::Get => get(root, &relpath, false),
        Method::Head => get(root, &relpath, true),
        Method::Put => put(root, &relpath, body),
        Method::Patch => patch(root, relpath, rq.headers(), body),
        Method::Options => options(),
        Method::Delete => delete(root, &relpath),
        m => match m.as_str() {
            "PROPFIND" => propfind(root, relpath, rq.headers(), body),
            "PROPPATCH" => proppatch(root, relpath, rq.headers(), body),
            "MKCOL" => mkcol(root, &relpath),
            "COPY" => copy(root, &relpath, rq.headers()),
            "MOVE" => move_(root, &relpath, rq.headers()),
            "LOCK" => Err(Error::NotImplemented),
            "UNLOCK" => Err(Error::NotImplemented),
            _ => Err(Error::NotImplemented),
        },
    }
}

fn path_normalize(uri: &str) -> Result<PathBuf, Error> {
    let mut components = Path::new(uri).components();

    if Some(Component::RootDir) != components.next() {
        return Err(status::FORBIDDEN.into());
    }

    let mut buf = PathBuf::new();
    for component in components {
        match component {
            Component::Prefix(_) | Component::RootDir => return Err(status::FORBIDDEN.into()),
            Component::CurDir => {} // skip
            Component::ParentDir => {
                if !buf.pop() {
                    return Err(status::FORBIDDEN.into());
                }
            }
            Component::Normal(_) => buf.push(component),
        }
    }
    Ok(buf)
}

fn get(root: &Path, relpath: &Path, head: bool) -> Result<ResponseBox, Error> {
    let path = root
        .join(&relpath)
        .canonicalize()
        .map_err(|_| status::NOT_FOUND)?;

    if path.is_dir() {
        use std::fmt::Write;

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
                .strip_prefix(root)
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
            .with_header(Header::from_bytes(CONTENT_TYPE.0, b"text/html; charset=utf-8").unwrap())
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
        Ok(res)
    } else {
        Err(status::NOT_FOUND.into())
    }
}

fn put(root: &Path, relpath: &Path, body: Vec<u8>) -> Result<ResponseBox, Error> {
    let path = root.join(relpath);
    let mut file = std::fs::File::create(&path)?;
    file.write_all(&body)?;
    Ok(Response::empty(status::CREATED).boxed())
}

fn patch(
    root: &Path,
    path: PathBuf,
    headers: &[Header],
    body: Vec<u8>,
) -> Result<ResponseBox, Error> {
    let path = path.canonicalize().map_err(|_| status::NOT_FOUND)?;
    path.strip_prefix(root).map_err(|_| status::FORBIDDEN)?;

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
        Some(_) => return Err(status::NOT_FOUND.into()),
        None => std::fs::OpenOptions::new().append(true).open(&path)?,
    };
    file.write_all(&body)?;
    Ok(Response::empty(status::NO_CONTENT).boxed())
}

fn options() -> Result<ResponseBox, Error> {
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

fn delete(root: &Path, relpath: &Path) -> Result<ResponseBox, Error> {
    let path = root.join(relpath);
    let meta = std::fs::metadata(&path)?;
    if meta.is_file() {
        std::fs::remove_file(&path)?;
    } else if meta.is_dir() {
        std::fs::remove_dir_all(&path)?;
    } else {
        return Err(status::NOT_FOUND.into());
    }
    Ok(Response::empty(status::NO_CONTENT).boxed())
}

fn propfind(
    root: &Path,
    relpath: PathBuf,
    headers: &[Header],
    body: Vec<u8>,
) -> Result<ResponseBox, Error> {
    let path = root.join(relpath);

    let _propfind = if !body.is_empty() {
        let body = String::from_utf8(body).map_err(|_| Error::Xml)?;
        info!("{body}");
        quick_xml::de::from_str(&body)?
    } else {
        PropFind::default()
    };

    let mut out = MultiStatus::new();
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
            out.response.push(PropResponse::new(&path, &meta, root)?)
        } else {
            let mut stream = read_dir_rec(&path, depth)?;
            while let Some(entry) = stream.pop() {
                out.response
                    .push(PropResponse::new(&entry.path(), &entry.metadata()?, root)?);
            }
        }
    } else if meta.is_file() {
        out.response.push(PropResponse::new(&path, &meta, root)?);
    } else {
        // We currently don't support symlinks
        return Err(status::NOT_FOUND.into());
    }
    info!("{out:?}");

    let out = format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\" ?>{}",
        quick_xml::se::to_string(&out)?
    );
    Ok(Response::from_string(out)
        .with_header(Header::from_bytes(CONTENT_TYPE.0, b"text/xml; charset=\"utf-8\"").unwrap())
        .with_status_code(status::MULTI_STATUS)
        .boxed())
}

fn proppatch(
    _root: &Path,
    _path: PathBuf,
    _headers: &[Header],
    _body: Vec<u8>,
) -> Result<ResponseBox, Error> {
    Err(Error::NotImplemented)
}

fn mkcol(root: &Path, relpath: &Path) -> Result<ResponseBox, Error> {
    let path = root.join(relpath);
    if !path.parent().ok_or(status::FORBIDDEN)?.exists() {
        return Err(status::CONFLICT.into());
    }

    std::fs::create_dir(&path)?;
    Ok(Response::empty(status::CREATED).boxed())
}

fn extract_dst(root: &Path, headers: &[Header]) -> Option<PathBuf> {
    let dst = headers.iter().find(|h| h.field == DESTINATION)?;
    let uri = Url::parse(dst.value.as_str()).ok()?;
    let path = path_normalize(uri.path()).ok()?;
    Some(root.join(path))
}

fn copy(root: &Path, relpath: &Path, headers: &[Header]) -> Result<ResponseBox, Error> {
    let path = root.join(relpath);
    let mut dst = extract_dst(root, headers).ok_or(status::FORBIDDEN)?;

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
    if !dst.parent().ok_or(status::FORBIDDEN)?.exists() {
        return Err(status::CONFLICT.into());
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

fn move_(root: &Path, relpath: &Path, headers: &[Header]) -> Result<ResponseBox, Error> {
    let path = root.join(relpath);
    let mut dst = extract_dst(root, headers).ok_or(Error::Header(DESTINATION.0))?;

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
    if !dst.parent().ok_or(status::FORBIDDEN)?.exists() {
        return Err(status::CONFLICT.into());
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
            href: format!(
                "/{}",
                path.strip_prefix(base)
                    .map_err(|_| status::NOT_FOUND)?
                    .display()
            ),
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
                            mime_guess::from_path(path)
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

fn date_str(time: SystemTime) -> String {
    DateTime::<Utc>::from(time).to_rfc3339()
}

#[cfg(test)]
mod test {
    use super::{byte_range, PropResponse};
    use crate::dav::{date_str, PropFind};
    use std::path::Path;

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

    #[test]
    fn prop_response() {
        let path = Path::new("src/");
        let base = Path::new("");
        let meta = path.metadata().unwrap();
        let res = PropResponse::new(path, &meta, base).unwrap();
        let xml = quick_xml::se::to_string(&res).unwrap();
        println!("{res:?}");
        println!("{xml}");

        let mtime = date_str(meta.modified().unwrap());
        let ctime = date_str(meta.created().unwrap());

        assert_eq!(
            xml,
            format!(
                "<PropResponse><href>/src</href><propstat><prop>\
                <creationdate>{ctime}</creationdate>\
                <displayname>src</displayname>\
                <getcontentlength>{}</getcontentlength>\
                <getcontenttype>text/plain</getcontenttype>\
                <resourcetype><collection/></resourcetype>\
                <getlastmodified>{mtime}</getlastmodified>\
                </prop><status>HTTP/1.1 200 OK</status></propstat></PropResponse>",
                meta.len(),
            )
        );
    }
}
