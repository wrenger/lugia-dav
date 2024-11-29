use std::{fs::Metadata, path::Path};

use serde::{Serialize, Serializer};
use tiny_http::StatusCode;

use crate::{
    dav::Error,
    status,
    util::{date_str, url_encode},
};

#[derive(Serialize, Debug)]
#[serde(rename = "multistatus")]
pub struct MultiStatus {
    #[serde(rename = "@xmlns", serialize_with = "MultiStatus::dav_ns")]
    xmlns: (),
    pub response: Vec<PropResponse>,
}
impl MultiStatus {
    pub fn new() -> Self {
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
pub struct PropResponse {
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
    pub fn new(path: &Path, meta: &Metadata, base: &Path) -> Result<Self, Error> {
        let display = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
            .into();

        Ok(Self {
            href: url_encode(
                &Path::new("/").join(path.strip_prefix(base).map_err(|_| status::NOT_FOUND)?),
            ),
            propstat: PropStat {
                prop: Prop {
                    prop: if meta.is_dir() {
                        vec![
                            PropKind::CreationDate(date_str(meta.created()?)),
                            PropKind::DisplayName(display),
                            PropKind::ResourceType(Some(PropCollection { collection: () })),
                            PropKind::GetLastModified(date_str(meta.modified()?)),
                        ]
                    } else {
                        let mime = mime_guess::from_path(path)
                            .first_or_text_plain()
                            .as_ref()
                            .into();
                        vec![
                            PropKind::CreationDate(date_str(meta.created()?)),
                            PropKind::DisplayName(display),
                            PropKind::GetContentLength(meta.len()),
                            PropKind::GetContentType(mime),
                            PropKind::ResourceType(None),
                            PropKind::GetLastModified(date_str(meta.modified()?)),
                        ]
                    },
                },
                status: status::OK,
            },
        })
    }
}

#[cfg(test)]
mod test {
    use std::path::Path;

    use crate::multi_status::PropResponse;
    use crate::util::date_str;

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
                <resourcetype><collection/></resourcetype>\
                <getlastmodified>{mtime}</getlastmodified>\
                </prop><status>HTTP/1.1 200 OK</status></propstat></PropResponse>",
            )
        );
    }
}
