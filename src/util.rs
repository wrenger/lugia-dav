use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use std::time::SystemTime;

use chrono::{DateTime, Utc};
use log::error;
use tiny_http::Header;
use url::Url;

use crate::dav::DESTINATION;

pub fn url_encode(p: &Path) -> String {
    Url::from_file_path(p)
        .map(|u| u.path().to_string())
        .unwrap_or_default()
}

pub fn header_destination(root: &Path, headers: &[Header]) -> Option<PathBuf> {
    let dst = headers.iter().find(|h| h.field == DESTINATION)?;
    let uri = Url::parse(dst.value.as_str()).ok()?;
    let path = parse_url_path(&uri)?;
    Some(root.join(path))
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

pub fn byte_range(range: &str, len: u64) -> Option<(u64, u64)> {
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

#[cfg(test)]
mod test {
    use std::path::Path;

    use crate::util::{byte_range, url_encode};

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
    }
}
