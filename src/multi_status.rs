use std::{fs::Metadata, path::Path};

use serde::{Serialize, Serializer};
use tiny_http::StatusCode;

use crate::{
    dav::Error,
    status,
    util::{date_str, http_date_str, url_encode},
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
#[serde(rename = "response")]
pub struct PropResponse {
    href: String,
    propstat: PropStat,
}

#[derive(Serialize, Debug)]
#[serde(rename = "propstat")]
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

impl PropKind {
    fn clear_value(&mut self) {
        match self {
            Self::CreationDate(value)
            | Self::DisplayName(value)
            | Self::GetContentType(value)
            | Self::GetLastModified(value) => value.clear(),
            Self::GetContentLength(value) => *value = 0,
            Self::ResourceType(value) => *value = None,
        }
    }

    fn name(&self) -> &'static str {
        match self {
            Self::CreationDate(_) => "creationdate",
            Self::DisplayName(_) => "displayname",
            Self::GetContentLength(_) => "getcontentlength",
            Self::GetContentType(_) => "getcontenttype",
            Self::GetLastModified(_) => "getlastmodified",
            Self::ResourceType(_) => "resourcetype",
        }
    }
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
                            PropKind::GetLastModified(http_date_str(meta.modified()?)),
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
                            PropKind::GetLastModified(http_date_str(meta.modified()?)),
                        ]
                    },
                },
                status: status::OK,
            },
        })
    }

    pub fn filter(&mut self, names: Option<&[String]>, names_only: bool) {
        if let Some(names) = names {
            self.propstat
                .prop
                .prop
                .retain(|property| names.iter().any(|name| property.name() == name));
        }
        if names_only {
            for property in &mut self.propstat.prop.prop {
                property.clear_value();
            }
        }
    }
}

#[cfg(test)]
mod test {
    use std::path::Path;

    use crate::multi_status::PropResponse;
    use crate::util::{date_str, http_date_str};

    #[test]
    fn prop_response() {
        let path = Path::new("src/");
        let base = Path::new("");
        let meta = path.metadata().unwrap();
        let res = PropResponse::new(path, &meta, base).unwrap();
        let xml = quick_xml::se::to_string(&res).unwrap();
        println!("{res:?}");
        println!("{xml}");

        let mtime = http_date_str(meta.modified().unwrap());
        let ctime = date_str(meta.created().unwrap());

        assert_eq!(
            xml,
            format!(
                "<response><href>/src</href><propstat><prop>\
                <creationdate>{ctime}</creationdate>\
                <displayname>src</displayname>\
                <resourcetype><collection/></resourcetype>\
                <getlastmodified>{mtime}</getlastmodified>\
                </prop><status>HTTP/1.1 200 OK</status></propstat></response>",
            )
        );
    }
}
