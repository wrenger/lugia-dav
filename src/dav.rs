use std::fs::File;
use std::io::{self, Seek, Write};
use std::io::{ErrorKind, SeekFrom};
use std::path::Path;
use std::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};

use facet::Facet;
use facet_xml::{self as xml, XmlError};
use log::{debug, error, info, warn};
use maud::{Markup, html};
use std::fs::DirEntry;
use tiny_http::{Header, HeaderField, Method, Request, Response, ResponseBox, StatusCode};

use crate::conditional::{self, ResourceState};
use crate::multi_status::{MultiStatus, PropResponse};
use crate::status;
use crate::util::{UpdateRange, header_destination, parse_path, safe_join, url_encode};

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
            Error::Xml => Response::from_string("XML serde error")
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
                // Some clients just love recreating already existing directories -> ignore
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
impl From<facet_xml::SerializeError<facet_xml::XmlSerializeError>> for Error {
    fn from(e: facet_xml::SerializeError<facet_xml::XmlSerializeError>) -> Self {
        error!("XML Serialize: {e:?}");
        Self::Xml
    }
}
impl From<facet_xml::DeserializeError<XmlError>> for Error {
    fn from(e: facet_xml::DeserializeError<XmlError>) -> Self {
        error!("XML Deserialize: {e:?}");
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

static FILESYSTEM: RwLock<()> = RwLock::new(());

enum RequestGuard {
    Read {
        _guard: RwLockReadGuard<'static, ()>,
    },
    Write {
        _guard: RwLockWriteGuard<'static, ()>,
    },
}

pub struct HandledResponse {
    response: ResponseBox,
    _guard: RequestGuard,
}

impl HandledResponse {
    pub fn respond(self, rq: Request) -> io::Result<()> {
        // Keep the guard until streaming finishes, so the body agrees with its validators.
        let Self { response, _guard } = self;
        rq.respond(response)
    }
}

pub fn handle(root: &Path, rq: &mut Request) -> Result<HandledResponse, Error> {
    debug!(
        "{} {} {:?}",
        rq.method(),
        rq.url(),
        rq.headers()
            .iter()
            .filter(|h| !h.field.equiv("Authorization"))
            .map(|h| h.to_string())
            .collect::<Vec<_>>()
    );

    let relpath = parse_path(rq.url()).ok_or(status::BAD_REQUEST)?;

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

    let guard = if matches!(rq.method(), Method::Get | Method::Head | Method::Options)
        || rq.method().as_str() == "PROPFIND"
    {
        RequestGuard::Read {
            _guard: FILESYSTEM.read().map_err(|_| Error::Internal)?,
        }
    } else {
        RequestGuard::Write {
            _guard: FILESYSTEM.write().map_err(|_| Error::Internal)?,
        }
    };
    let response = handle_locked(root, &relpath, rq, body)?;
    Ok(HandledResponse {
        response,
        _guard: guard,
    })
}

fn handle_locked(
    root: &Path,
    relpath: &Path,
    rq: &Request,
    body: Vec<u8>,
) -> Result<ResponseBox, Error> {
    let supported = matches!(
        rq.method(),
        Method::Get | Method::Head | Method::Put | Method::Patch | Method::Options | Method::Delete
    ) || matches!(rq.method().as_str(), "PROPFIND" | "MKCOL" | "COPY" | "MOVE");
    if !supported {
        return Err(Error::NotImplemented);
    }

    let path = safe_join(root, relpath).ok_or(status::FORBIDDEN)?;
    let state = ResourceState::read(&path)?;
    // Conditions do not turn ordinary request errors into 304/412 responses.
    if !state.exists
        && !matches!(rq.method(), Method::Put | Method::Options)
        && rq.method().as_str() != "MKCOL"
    {
        return Err(status::NOT_FOUND.into());
    }
    if (rq.method() == &Method::Put && path.is_dir())
        || (rq.method().as_str() == "MKCOL" && state.exists)
    {
        return Err(status::METHOD_NOT_ALLOWED.into());
    }
    validate_request(root, &path, rq, &body)?;
    if let Some(code) = conditional::evaluate(rq.method(), rq.headers(), &state, |tag| {
        resolve_condition_resource(root, rq, tag)
    })? {
        return Ok(with_validators(Response::empty(code).boxed(), &state));
    }
    let response = dispatch(root, relpath, rq, body)?;
    if matches!(rq.method(), Method::Get | Method::Head) {
        Ok(with_validators(response, &state))
    } else if matches!(rq.method(), Method::Put | Method::Patch) {
        match ResourceState::read(&path) {
            Ok(state) => Ok(with_validators(response, &state)),
            Err(error) => {
                // The mutation has committed; failing here could trigger an unsafe retry.
                warn!("could not generate validators after writing {path:?}: {error:?}");
                Ok(response)
            }
        }
    } else {
        Ok(response)
    }
}

fn validate_request(root: &Path, path: &Path, rq: &Request, body: &[u8]) -> Result<(), Error> {
    if (rq.method() == &Method::Put || rq.method().as_str() == "MKCOL")
        && !path.parent().ok_or(status::FORBIDDEN)?.exists()
    {
        return Err(status::CONFLICT.into());
    }
    match rq.method() {
        Method::Patch => {
            patch_offset(rq.headers(), path.metadata()?.len(), body.len())?;
        }
        method => match method.as_str() {
            "COPY" | "MOVE" => {
                if method.as_str() == "COPY" {
                    copy_depth(rq.headers())?;
                }
                parse_overwrite(rq.headers())?;
                transfer_destination(root, path, path.is_dir(), rq.headers())?;
            }
            "PROPFIND" => {
                parse_propfind(body)?;
                if path.is_dir() {
                    propfind_depth(rq.headers())?;
                }
            }
            _ => {}
        },
    }
    Ok(())
}

fn with_validators(mut response: ResponseBox, state: &ResourceState) -> ResponseBox {
    if let Some(etag) = &state.etag {
        response.add_header(Header::from_bytes("ETag", etag.as_str()).unwrap());
    }
    if let Some(modified) = state.modified {
        response.add_header(
            Header::from_bytes("Last-Modified", crate::util::http_date_str(modified)).unwrap(),
        );
    }
    response
}

fn resolve_condition_resource(
    root: &Path,
    rq: &Request,
    tag: &str,
) -> Result<ResourceState, Error> {
    let relpath = if tag.starts_with('/') {
        parse_path(tag).ok_or(status::BAD_REQUEST)?
    } else {
        let uri = url::Url::parse(tag).map_err(|_| status::BAD_REQUEST)?;
        if uri.query().is_some()
            || uri.fragment().is_some()
            || !uri.username().is_empty()
            || uri.password().is_some()
        {
            return Err(status::BAD_REQUEST.into());
        }
        let host = rq
            .headers()
            .iter()
            .find(|h| h.field.equiv("Host"))
            .ok_or(status::BAD_REQUEST)?;
        let scheme = if rq.secure() { "https" } else { "http" };
        let origin = url::Url::parse(&format!("{scheme}://{}/", host.value))
            .map_err(|_| status::BAD_REQUEST)?;
        if uri.origin() != origin.origin() {
            // Never fetch remote tags or alias them to a local path.
            return Ok(ResourceState {
                exists: false,
                etag: None,
                modified: None,
            });
        }
        parse_path(uri.path()).ok_or(status::BAD_REQUEST)?
    };
    let path = safe_join(root, &relpath).ok_or(status::FORBIDDEN)?;
    ResourceState::read(&path)
}

fn dispatch(
    root: &Path,
    relpath: &Path,
    rq: &Request,
    body: Vec<u8>,
) -> Result<ResponseBox, Error> {
    match rq.method() {
        Method::Get | Method::Head => get(root, relpath),
        Method::Put => put(root, relpath, body),
        Method::Patch => patch(root, relpath, rq.headers(), body),
        Method::Options => options(),
        Method::Delete => delete(root, relpath),
        m => match m.as_str() {
            "PROPFIND" => propfind(root, relpath, rq.headers(), body),
            "PROPPATCH" => proppatch(root, relpath, rq.headers(), body),
            "MKCOL" => mkcol(root, relpath),
            "COPY" => copy(root, relpath, rq.headers()),
            "MOVE" => move_(root, relpath, rq.headers()),
            "LOCK" => Err(Error::NotImplemented),
            "UNLOCK" => Err(Error::NotImplemented),
            _ => Err(Error::NotImplemented),
        },
    }
}

fn get(root: &Path, relpath: &Path) -> Result<ResponseBox, Error> {
    let path = safe_join(root, relpath).ok_or(status::NOT_FOUND)?;

    if path.is_dir() {
        let str_path = relpath.to_string_lossy();
        fn page(title: &str, body: Markup) -> Markup {
            html! {
                (maud::DOCTYPE);
                html {
                    head {
                        meta charset="utf-8";
                        title { (title) }
                        meta viewport="width=device-width, initial-scale=1";
                        link rel="stylesheet" href="https://unpkg.com/sakura.css/css/sakura.css" media="screen";
                        link rel="stylesheet" href="https://unpkg.com/sakura.css/css/sakura-dark.css" media="screen and (prefers-color-scheme: dark)";
                    }
                    body { (body) }
                }
            }
        }
        let out = page(
            &str_path,
            html! {
                h1 { ("/") (str_path) }
                table width="100%" {
                    tr {
                        th width="100%" { "Name" }
                        th { "Type" }
                        th { "Size" }
                    }
                    @if let Some(parent) = relpath.parent() {
                        @let file_path = url_encode(&Path::new("/").join(parent));
                        tr {
                            td width="100%" { a href=(file_path) { ".." } }
                            td { "dir" }
                            td { "" }
                        }
                    }
                    @for entry in std::fs::read_dir(path.clone())? {
                        @let entry = entry?;
                        @let meta = entry.path().symlink_metadata()?;
                        @let file_type = entry.file_type()?;
                        @let kind = if file_type.is_file() {
                            "file"
                        } else if file_type.is_dir() {
                            "dir"
                        } else if file_type.is_symlink() {
                            "symlink"
                        } else {
                            "unknown"
                        };
                        @let file_path = url_encode(
                            &Path::new("/").join(
                                entry
                                    .path()
                                    .strip_prefix(root)
                                    .map_err(|_| Error::Internal)?,
                            ),
                        );
                        @let file_name = entry.file_name();
                        tr {
                            td width="100%" { a href=(file_path) { (file_name.to_string_lossy()) } }
                            td { (kind) }
                            td { (meta.len()) }
                        }
                    }
                }
            },
        );
        Ok(Response::from_string(out)
            .with_header(Header::from_bytes(CONTENT_TYPE.0, b"text/html; charset=utf-8").unwrap())
            .boxed())
    } else if path.is_file() {
        let res = Response::from_file(File::open(&path)?).boxed();
        Ok(res.with_header(
            Header::from_bytes(
                CONTENT_TYPE.0,
                mime_guess::from_path(&path).first_or_text_plain().as_ref(),
            )
            .unwrap(),
        ))
    } else {
        Err(status::NOT_FOUND.into())
    }
}

fn put(root: &Path, relpath: &Path, body: Vec<u8>) -> Result<ResponseBox, Error> {
    let path = safe_join(root, relpath).ok_or(status::FORBIDDEN)?;
    if path.is_dir() {
        return Err(status::METHOD_NOT_ALLOWED.into());
    }
    let existed = path.exists();
    if let Some(p) = path.parent()
        && !p.exists()
    {
        // PUT with missing intermediate -> 409
        return Err(status::CONFLICT.into());
    }
    let mut file = std::fs::File::create(&path)?;
    file.write_all(&body)?;
    Ok(Response::empty(if existed {
        status::NO_CONTENT
    } else {
        status::CREATED
    })
    .boxed())
}

fn patch(
    root: &Path,
    relpath: &Path,
    headers: &[Header],
    body: Vec<u8>,
) -> Result<ResponseBox, Error> {
    let path = safe_join(root, relpath).ok_or(status::NOT_FOUND)?;

    let meta = std::fs::metadata(&path)?;
    let offset = patch_offset(headers, meta.len(), body.len())?;

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

fn patch_offset(headers: &[Header], len: u64, body_len: usize) -> Result<Option<u64>, Error> {
    let Some(header) = headers.iter().find(|h| h.field == UPDATE_RANGE) else {
        return Ok(None);
    };
    match UpdateRange::parse(header.value.as_str()).ok_or(Error::Header(UPDATE_RANGE.0))? {
        UpdateRange::Append => Ok(None),
        UpdateRange::Bytes(range) => {
            let (start, end) = range.resolve(len).ok_or(Error::Header(UPDATE_RANGE.0))?;
            if end.checked_sub(start).and_then(|size| size.checked_add(1)) != Some(body_len as u64)
            {
                return Err(Error::Header(UPDATE_RANGE.0));
            }
            Ok(Some(start))
        }
    }
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
    let path = safe_join(root, relpath).ok_or(status::FORBIDDEN)?;
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
    relpath: &Path,
    headers: &[Header],
    body: Vec<u8>,
) -> Result<ResponseBox, Error> {
    let path = safe_join(root, relpath).ok_or(status::FORBIDDEN)?;

    let propfind = parse_propfind(&body)?;
    let names_only = matches!(&propfind.propfind, PropFindInner::PropName);
    let requested_names = match &propfind.propfind {
        PropFindInner::Prop { props } => Some(
            props
                .iter()
                .filter_map(PropFindKind::name)
                .map(str::to_owned)
                .collect::<Vec<_>>(),
        ),
        PropFindInner::AllProp | PropFindInner::PropName => None,
    };

    let include_etag = !names_only
        && requested_names
            .as_ref()
            .is_none_or(|names| names.iter().any(|name| name == "getetag"));
    let mut out = MultiStatus::new();
    let meta = std::fs::metadata(&path)?;
    if meta.is_dir() {
        let depth = propfind_depth(headers)?;

        let mut response = PropResponse::new(&path, &meta, root, include_etag)?;
        response.filter(requested_names.as_deref(), names_only);
        out.response.push(response);

        if depth > 0 {
            let mut stream = read_dir_rec(&path, depth)?;
            while let Some(entry) = stream.pop() {
                let mut response =
                    PropResponse::new(&entry.path(), &entry.metadata()?, root, include_etag)?;
                response.filter(requested_names.as_deref(), names_only);
                out.response.push(response);
            }
        }
    } else if meta.is_file() {
        let mut response = PropResponse::new(&path, &meta, root, include_etag)?;
        response.filter(requested_names.as_deref(), names_only);
        out.response.push(response);
    } else {
        // We currently don't support symlinks
        return Err(status::NOT_FOUND.into());
    }
    debug!("{out:?}");

    let out = format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\" ?>{}",
        facet_xml::to_string(&out)?
    );
    Ok(Response::from_string(out)
        .with_header(Header::from_bytes(CONTENT_TYPE.0, b"text/xml; charset=\"utf-8\"").unwrap())
        .with_status_code(status::MULTI_STATUS)
        .boxed())
}

fn parse_propfind(body: &[u8]) -> Result<PropFind, Error> {
    if body.is_empty() {
        Ok(PropFind::default())
    } else {
        let body = std::str::from_utf8(body).map_err(|_| Error::Xml)?;
        info!("{body}");
        Ok(facet_xml::from_str(body)?)
    }
}

fn propfind_depth(headers: &[Header]) -> Result<usize, Error> {
    headers
        .iter()
        .find(|header| header.field == DEPTH)
        .map(|header| parse_depth(header.value.as_str()))
        .transpose()
        .map(|depth| depth.unwrap_or(usize::MAX))
}

fn proppatch(
    _root: &Path,
    _path: &Path,
    _headers: &[Header],
    _body: Vec<u8>,
) -> Result<ResponseBox, Error> {
    Err(Error::NotImplemented)
}

fn mkcol(root: &Path, relpath: &Path) -> Result<ResponseBox, Error> {
    let path = safe_join(root, relpath).ok_or(status::FORBIDDEN)?;
    if path.exists() {
        return Err(status::METHOD_NOT_ALLOWED.into());
    }
    if !path.parent().ok_or(status::FORBIDDEN)?.exists() {
        return Err(status::CONFLICT.into());
    }

    std::fs::create_dir(&path)?;
    Ok(Response::empty(status::CREATED).boxed())
}

fn copy(root: &Path, relpath: &Path, headers: &[Header]) -> Result<ResponseBox, Error> {
    let path = safe_join(root, relpath).ok_or(status::FORBIDDEN)?;
    let source_meta = std::fs::metadata(&path)?;
    let source_is_dir = source_meta.is_dir();
    let depth = copy_depth(headers)?;
    let overwrite = parse_overwrite(headers)?;
    let (dst, destination_collection) = transfer_destination(root, &path, source_is_dir, headers)?;

    // A depth-zero collection copy creates only the collection itself.
    // Remove overwritten files
    let destination_existed = dst.exists();
    if destination_existed {
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

    if source_is_dir {
        std::fs::create_dir(&dst)?;
        if depth > 0 {
            copy_dir_contents(&path, &dst)?;
        }
    } else {
        let e = std::fs::copy(&path, &dst);
        if let Err(e) = e {
            warn!("{e:?}");
            return Err(e.into());
        }
    }

    if destination_existed || (destination_collection && overwrite) {
        Ok(Response::empty(status::NO_CONTENT).boxed())
    } else {
        Ok(Response::empty(status::CREATED).boxed())
    }
}

fn move_(root: &Path, relpath: &Path, headers: &[Header]) -> Result<ResponseBox, Error> {
    let path = safe_join(root, relpath).ok_or(status::FORBIDDEN)?;
    let source_meta = std::fs::metadata(&path)?;
    let source_is_dir = source_meta.is_dir();
    let overwrite = parse_overwrite(headers)?;
    let (dst, destination_collection) = transfer_destination(root, &path, source_is_dir, headers)?;

    let destination_existed = dst.exists();
    if destination_existed && !overwrite {
        return Err(Error::Status(status::PRECONDITION_FAILED));
    }

    // Rename preserves mtimes, but the representations at the destination URLs change.
    // Refresh them before deleting the destination so timestamp errors cannot destroy it.
    let modified = std::time::SystemTime::now();
    if source_is_dir {
        for entry in read_dir_rec(&path, usize::MAX)? {
            if entry.file_type()?.is_file() {
                File::open(entry.path())?.set_modified(modified)?;
            }
        }
    } else {
        File::open(&path)?.set_modified(modified)?;
    }

    // Remove overwritten files
    if destination_existed {
        warn!("overwriting {:?}", dst);
        if dst.is_file() {
            std::fs::remove_file(&dst)?;
        } else if dst.is_dir() {
            std::fs::remove_dir_all(&dst)?;
        }
    }

    std::fs::rename(&path, &dst)?;

    if destination_existed || (destination_collection && overwrite) {
        Ok(Response::empty(status::NO_CONTENT).boxed())
    } else {
        Ok(Response::empty(status::CREATED).boxed())
    }
}

fn transfer_destination(
    root: &Path,
    path: &Path,
    source_is_dir: bool,
    headers: &[Header],
) -> Result<(std::path::PathBuf, bool), Error> {
    let mut dst = header_destination(root, headers).ok_or(Error::Header(DESTINATION.0))?;
    let destination_collection = !source_is_dir && dst.is_dir();
    if destination_collection {
        dst = safe_join(&dst, Path::new(path.file_name().ok_or(status::FORBIDDEN)?))
            .ok_or(status::FORBIDDEN)?;
    }
    if !dst.parent().ok_or(status::FORBIDDEN)?.exists() {
        return Err(status::CONFLICT.into());
    }
    if path.starts_with(&dst) || (source_is_dir && dst.starts_with(path)) {
        return Err(status::FORBIDDEN.into());
    }
    Ok((dst, destination_collection))
}

fn copy_depth(headers: &[Header]) -> Result<usize, Error> {
    headers
        .iter()
        .find(|header| header.field == DEPTH)
        .map(|header| parse_copy_depth(header.value.as_str()))
        .transpose()
        .map(|depth| depth.unwrap_or(usize::MAX))
}

fn parse_overwrite(headers: &[Header]) -> Result<bool, Error> {
    let Some(header) = headers.iter().find(|header| header.field == OVERWRITE) else {
        return Ok(true);
    };
    match header.value.as_str() {
        "1" | "t" | "T" => Ok(true),
        "0" | "f" | "F" => Ok(false),
        _ => Err(Error::Header(OVERWRITE.0)),
    }
}

fn parse_copy_depth(value: &str) -> Result<usize, Error> {
    match value {
        "0" => Ok(0),
        "infinity" => Ok(usize::MAX),
        _ => Err(Error::Header(DEPTH.0)),
    }
}

fn copy_dir_contents(src: &Path, dst: &Path) -> io::Result<()> {
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let target = dst.join(entry.file_name());
        let file_type = entry.file_type()?;
        if file_type.is_symlink() {
            return Err(io::Error::new(
                ErrorKind::PermissionDenied,
                "symlinks are not supported",
            ));
        }
        if file_type.is_dir() {
            std::fs::create_dir(&target)?;
            copy_dir_contents(&entry.path(), &target)?;
        } else {
            std::fs::copy(entry.path(), target)?;
        }
    }
    Ok(())
}

fn parse_depth(value: &str) -> Result<usize, Error> {
    match value {
        "0" => Ok(0),
        "1" => Ok(1),
        "infinity" => Ok(usize::MAX),
        _ => Err(Error::Header(DEPTH.0)),
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

        let file_type = entry.file_type()?;
        if file_type.is_symlink() {
            continue;
        }
        if depth > dirs.len() && file_type.is_dir() {
            dirs.push(std::fs::read_dir(entry.path())?);
        }
        res.push(entry);
    }
}

#[derive(Facet, Debug, Default)]
#[facet(rename = "propfind")]
struct PropFind {
    #[facet(flatten)]
    propfind: PropFindInner,
}

#[derive(Facet, Debug, Default)]
#[facet(rename_all = "lowercase")]
#[repr(u8)]
enum PropFindInner {
    Prop {
        #[facet(flatten, default)]
        props: Vec<PropFindKind>,
    },
    PropName,
    #[default]
    AllProp,
}

#[derive(Facet, Debug)]
#[facet(rename_all = "lowercase")]
#[repr(u8)]
enum PropFindKind {
    CreationDate,
    DisplayName,
    ResourceType,
    GetContentLength,
    GetContentType,
    GetEtag,
    GetLastModified,
    #[facet(xml::custom_element, skip_serializing)]
    Other,
}

impl PropFindKind {
    fn name(&self) -> Option<&'static str> {
        match self {
            Self::CreationDate => Some("creationdate"),
            Self::DisplayName => Some("displayname"),
            Self::ResourceType => Some("resourcetype"),
            Self::GetContentLength => Some("getcontentlength"),
            Self::GetContentType => Some("getcontenttype"),
            Self::GetEtag => Some("getetag"),
            Self::GetLastModified => Some("getlastmodified"),
            Self::Other => None,
        }
    }
}

#[cfg(test)]
mod test {
    use rediff::assert_same;

    use crate::dav::PropFind;

    #[cfg(unix)]
    #[test]
    fn writes_succeed_on_unreadable_files() {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;
        use std::time::{SystemTime, UNIX_EPOCH};

        use tiny_http::{Method, Request, TestRequest};

        let id = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "lugia-dav-write-validators-{}-{id}",
            std::process::id()
        ));
        fs::create_dir(&root).unwrap();
        let path = root.join("file");

        for mode in [0o600, 0o200] {
            for method in [Method::Put, Method::Patch] {
                fs::write(&path, b"old").unwrap();
                fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
                let expected = if method == Method::Put {
                    "new"
                } else {
                    "oldnew"
                };
                let mut rq: Request = TestRequest::new()
                    .with_method(method)
                    .with_path("/file")
                    .with_body("new")
                    .into();
                let response = super::handle(&root, &mut rq).unwrap();
                assert_eq!(response.response.status_code(), crate::status::NO_CONTENT);
                // Validators come from metadata, so they are available
                // even when the file cannot be opened for reading.
                for name in ["ETag", "Last-Modified"] {
                    assert!(
                        response
                            .response
                            .headers()
                            .iter()
                            .any(|h| h.field.equiv(name)),
                        "{name}, mode {mode:o}"
                    );
                }
                response.respond(rq).unwrap();
                fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
                assert_eq!(fs::read_to_string(&path).unwrap(), expected);
            }
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn patch_ranges_validate_offsets_and_body_lengths() {
        use tiny_http::Header;

        assert_eq!(super::patch_offset(&[], 0, 3).unwrap(), None);
        for (value, len, body_len, expected) in [
            ("append", 0, 3, None),
            ("append", 10, 3, None),
            ("bytes=2-4", 10, 3, Some(2)),
            ("bytes=7-", 10, 3, Some(7)),
            ("bytes=-3", 10, 3, Some(7)),
        ] {
            let headers = [Header::from_bytes("X-Update-Range", value).unwrap()];
            assert_eq!(
                super::patch_offset(&headers, len, body_len).unwrap(),
                expected,
                "{value}"
            );
        }
        for (value, len, body_len) in [
            ("bytes=2-4", 10, 2),
            ("bytes=2-4", 10, 4),
            ("bytes=10-", 10, 0),
            ("bytes=-11", 10, 11),
            ("bytes=-0", 10, 0),
            ("bytes=0-", 0, 0),
            ("bytes=4-2", 10, 3),
            ("append trailing", 10, 3),
            ("bytes=1-2 trailing", 10, 2),
            ("bytes=+1-2", 10, 2),
            ("bytes=18446744073709551616-", 10, 1),
        ] {
            let headers = [Header::from_bytes("X-Update-Range", value).unwrap()];
            assert!(
                matches!(
                    super::patch_offset(&headers, len, body_len),
                    Err(super::Error::Header(_))
                ),
                "{value}"
            );
        }
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

        let propfind: PropFind = facet_xml::from_str(xml).unwrap();
        assert_same!(
            propfind.propfind,
            super::PropFindInner::Prop {
                props: vec![
                    super::PropFindKind::GetContentLength,
                    super::PropFindKind::GetLastModified,
                    super::PropFindKind::DisplayName,
                    super::PropFindKind::ResourceType,
                    super::PropFindKind::Other,
                    super::PropFindKind::Other,
                ]
            }
        );
    }

    #[test]
    fn propfind_request_forms() {
        for body in [
            "",
            r#"<propfind xmlns="DAV:"><allprop/></propfind>"#,
            r#"<D:propfind xmlns:D="DAV:"><D:allprop/></D:propfind>"#,
        ] {
            let request = super::parse_propfind(body.as_bytes()).unwrap();
            assert_same!(request.propfind, super::PropFindInner::AllProp);
        }
        let request =
            super::parse_propfind(br#"<D:propfind xmlns:D="DAV:"><D:propname/></D:propfind>"#)
                .unwrap();
        assert_same!(request.propfind, super::PropFindInner::PropName);

        let request =
            super::parse_propfind(br#"<D:propfind xmlns:D="DAV:"><D:prop/></D:propfind>"#).unwrap();
        assert_same!(
            request.propfind,
            super::PropFindInner::Prop { props: Vec::new() }
        );
    }

    #[test]
    fn copy_move_to_ancestor_preserves_data() {
        use std::fs;
        use std::path::Path;
        use std::time::{SystemTime, UNIX_EPOCH};

        use tiny_http::Header;

        let id = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let base =
            std::env::temp_dir().join(format!("lugia-dav-ancestor-{}-{id}", std::process::id()));

        for method in ["COPY", "MOVE"] {
            for (index, destination) in ["/parent", "/"].into_iter().enumerate() {
                for depth in ["0", "infinity"] {
                    let root = base.join(format!("{method}-{index}-{depth}"));
                    fs::create_dir_all(root.join("parent/child")).unwrap();
                    fs::write(root.join("parent/child/data"), b"source").unwrap();
                    fs::write(root.join("parent/sibling"), b"sibling").unwrap();
                    let headers = [
                        Header::from_bytes("Destination", destination).unwrap(),
                        Header::from_bytes("Depth", depth).unwrap(),
                    ];

                    let result = if method == "COPY" {
                        super::copy(&root, Path::new("parent/child"), &headers)
                    } else {
                        super::move_(&root, Path::new("parent/child"), &headers)
                    };

                    assert!(matches!(
                        result,
                        Err(super::Error::Status(crate::status::FORBIDDEN))
                    ));
                    assert_eq!(fs::read(root.join("parent/child/data")).unwrap(), b"source");
                    assert_eq!(fs::read(root.join("parent/sibling")).unwrap(), b"sibling");
                }
            }
        }

        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn move_overwrite_refreshes_last_modified() {
        use std::fs;
        use std::time::{Duration, SystemTime, UNIX_EPOCH};

        use tiny_http::{Header, Method, Request, TestRequest};

        let id = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let base = std::env::temp_dir().join(format!(
            "lugia-dav-move-modified-{}-{id}",
            std::process::id()
        ));
        let source_time = UNIX_EPOCH + Duration::from_secs(100);
        let cached_time = UNIX_EPOCH + Duration::from_secs(200);
        let cached_date = crate::util::http_date_str(cached_time);

        for collection in [false, true] {
            let root = base.join(if collection { "collection" } else { "file" });
            fs::create_dir_all(&root).unwrap();
            let (source_file, destination_file, destination_url) = if collection {
                fs::create_dir_all(root.join("source/nested")).unwrap();
                fs::create_dir_all(root.join("destination/nested")).unwrap();
                (
                    "source/nested/file",
                    "destination/nested/file",
                    "/destination/nested/file",
                )
            } else {
                ("source", "destination", "/destination")
            };
            fs::write(root.join(source_file), b"replacement").unwrap();
            fs::write(root.join(destination_file), b"cached content").unwrap();
            fs::File::open(root.join(source_file))
                .unwrap()
                .set_modified(source_time)
                .unwrap();
            fs::File::open(root.join(destination_file))
                .unwrap()
                .set_modified(cached_time)
                .unwrap();

            let mut rq: Request = TestRequest::new()
                .with_method("MOVE".parse().unwrap())
                .with_path("/source")
                .with_header(Header::from_bytes("Destination", "/destination").unwrap())
                .into();
            let response = super::handle(&root, &mut rq).unwrap();
            assert_eq!(response.response.status_code(), crate::status::NO_CONTENT);
            response.respond(rq).unwrap();
            assert!(!root.join("source").exists());
            assert_eq!(
                fs::read(root.join(destination_file)).unwrap(),
                b"replacement"
            );

            for method in [Method::Get, Method::Head] {
                let mut rq: Request = TestRequest::new()
                    .with_method(method)
                    .with_path(destination_url)
                    .with_header(
                        Header::from_bytes("If-Modified-Since", cached_date.as_str()).unwrap(),
                    )
                    .into();
                let response = super::handle(&root, &mut rq).unwrap();
                assert_eq!(response.response.status_code(), crate::status::OK);
                let modified = response
                    .response
                    .headers()
                    .iter()
                    .find(|header| header.field.equiv("Last-Modified"))
                    .unwrap();
                assert!(httpdate::parse_http_date(modified.value.as_str()).unwrap() > cached_time);
                response.respond(rq).unwrap();
            }
        }
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn depth_values() {
        assert_eq!(super::parse_depth("0").unwrap(), 0);
        assert_eq!(super::parse_depth("1").unwrap(), 1);
        assert_eq!(super::parse_depth("infinity").unwrap(), usize::MAX);
        assert!(super::parse_depth("2").is_err());
        assert!(super::parse_depth("Infinity").is_err());

        assert_eq!(super::parse_copy_depth("0").unwrap(), 0);
        assert_eq!(super::parse_copy_depth("infinity").unwrap(), usize::MAX);
        assert!(super::parse_copy_depth("1").is_err());
        assert!(super::parse_copy_depth("Infinity").is_err());
    }
}
