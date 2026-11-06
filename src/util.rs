use std::io::ErrorKind;
use std::path::{Component, Path, PathBuf};
use std::sync::LazyLock;
use std::time::SystemTime;

use chrono::{DateTime, Utc};
use log::error;
use tiny_http::Header;
use url::Url;
use winnow::ascii::dec_uint;
use winnow::combinator::{alt, opt, preceded};
use winnow::{ModalResult, Parser};

use crate::dav::DESTINATION;

pub fn url_encode(p: &Path) -> String {
    Url::from_file_path(p)
        .map(|u| u.path().to_string())
        .unwrap_or_default()
}

pub fn header_destination(root: &Path, headers: &[Header]) -> Option<PathBuf> {
    static BASE: LazyLock<Url> = LazyLock::new(|| Url::parse("https://localhost").unwrap());

    let dst = headers.iter().find(|h| h.field == DESTINATION)?;
    let uri = Url::options()
        .base_url(Some(&BASE))
        .parse(dst.value.as_str())
        .ok()?;
    let path = parse_url_path(&uri)?;
    safe_join(root, &path)
}

pub fn safe_join(root: &Path, relpath: &Path) -> Option<PathBuf> {
    let mut current = root.canonicalize().ok()?;
    for component in relpath.components() {
        let name = match component {
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return None,
            Component::CurDir => continue,
            Component::Normal(name) => name,
        };

        current.push(name);
        // Not follow symlinks
        match current.symlink_metadata() {
            Ok(metadata) if metadata.file_type().is_symlink() => return None,
            Ok(_) => {}
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(_) => return None,
        }
    }
    Some(current)
}

pub fn parse_path(p: &str) -> Option<PathBuf> {
    static BASE: LazyLock<Url> = LazyLock::new(|| Url::parse("https://localhost").unwrap());

    let url = Url::options().base_url(Some(&BASE)).parse(p).ok()?;
    parse_url_path(&url)
}

fn parse_url_path(url: &Url) -> Option<PathBuf> {
    if url.fragment().is_some()
        || url.query().is_some()
        || url.password().is_some()
        || !url.username().is_empty()
    {
        error!("path {url}");
        return None;
    }
    let abspath = url.to_file_path().ok()?;
    let relpath = abspath.strip_prefix("/").ok()?;
    Some(relpath.into())
}

pub fn date_str(time: SystemTime) -> String {
    DateTime::<Utc>::from(time).to_rfc3339()
}

pub fn http_date_str(time: SystemTime) -> String {
    DateTime::<Utc>::from(time)
        .format("%a, %d %b %Y %H:%M:%S GMT")
        .to_string()
}

#[derive(Debug, PartialEq, Eq)]
pub enum ByteRange {
    Inclusive { start: u64, end: u64 },
    From(u64),
    Suffix(u64),
}

impl ByteRange {
    pub fn resolve(self, len: u64) -> Option<(u64, u64)> {
        let last = len.checked_sub(1)?;
        let (start, end) = match self {
            Self::Inclusive { start, end } => (start, end),
            Self::From(start) => (start, last),
            Self::Suffix(size) => (len.checked_sub(size)?, last),
        };
        (start <= end && end < len).then_some((start, end))
    }
}

fn byte_range(input: &mut &str) -> ModalResult<ByteRange> {
    preceded(
        "bytes=",
        alt((
            preceded('-', dec_uint).map(ByteRange::Suffix),
            (dec_uint, '-', opt(dec_uint)).map(|(start, _, end)| match end {
                Some(end) => ByteRange::Inclusive { start, end },
                None => ByteRange::From(start),
            }),
        )),
    )
    .parse_next(input)
}

#[derive(Debug, PartialEq, Eq)]
pub enum UpdateRange {
    Append,
    Bytes(ByteRange),
}

impl UpdateRange {
    pub fn parse(value: &str) -> Option<Self> {
        alt(("append".map(|_| Self::Append), byte_range.map(Self::Bytes)))
            .parse(value)
            .ok()
    }
}

#[cfg(test)]
mod test {
    use std::path::Path;

    use crate::util::{url_encode, ByteRange, UpdateRange};
    use winnow::Parser;

    fn byte_range(value: &str, len: u64) -> Option<(u64, u64)> {
        super::byte_range.parse(value).ok()?.resolve(len)
    }

    #[test]
    fn url_path() {
        let url = url_encode(Path::new("/foo/bar/baz/<>??"));
        println!("{url}");

        let url = url_encode(Path::new("/foo/bar/../"));
        println!("{url}");

        let url = url_encode(Path::new("/foo/../data.bin"));
        println!("{url}");

        assert!(url_encode(Path::new("http://localhost/foo/../baz/tmp/")).is_empty());
    }

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
        assert_eq!(byte_range("bytes=499-0", 500), None);
        assert_eq!(byte_range("bytes=-0", 500), None);
        for value in ["bytes=0-", "bytes=-0", "bytes=-1", "bytes=0-0"] {
            assert_eq!(byte_range(value, 0), None, "{value}");
        }
        assert_eq!(byte_range("bytes=0-", u64::MAX), Some((0, u64::MAX - 1)));
        assert_eq!(
            byte_range("bytes=-18446744073709551615", u64::MAX),
            Some((0, u64::MAX - 1))
        );
    }

    #[test]
    fn update_range_syntax() {
        for (value, expected) in [
            ("append", UpdateRange::Append),
            (
                "bytes=2-4",
                UpdateRange::Bytes(ByteRange::Inclusive { start: 2, end: 4 }),
            ),
            ("bytes=2-", UpdateRange::Bytes(ByteRange::From(2))),
            ("bytes=-3", UpdateRange::Bytes(ByteRange::Suffix(3))),
        ] {
            assert_eq!(UpdateRange::parse(value), Some(expected), "{value}");
        }
        for value in [
            "",
            "APPEND",
            "append trailing",
            "bytes=-",
            "bytes=+1-2",
            "bytes=1-+2",
            "bytes=1--2",
            "bytes=1-2-3",
            "bytes=1-2,4-5",
            "bytes=1-2 trailing",
            "bytes= 1-2",
            "bytes=1-2 ",
            "bytes=18446744073709551616-",
            "bytes=-18446744073709551616",
        ] {
            assert_eq!(UpdateRange::parse(value), None, "{value}");
        }
    }
}
