use std::convert::Infallible;
use std::{fs::Metadata, path::Path};

use facet::Facet;
use facet_xml as xml;
use tiny_http::StatusCode;
use winnow::Parser as _;
use winnow::ascii::{dec_uint, space1};
use winnow::combinator::delimited;
use winnow::error::ContextError;
use winnow::token::rest;

use crate::conditional::file_etag;
use crate::dav::Error;
use crate::status;
use crate::util::{date_str, http_date_str, url_encode};

#[derive(Facet, Debug)]
#[facet(rename = "multistatus")]
pub struct MultiStatus {
    #[facet(xml::attribute)]
    xmlns: &'static str,
    pub response: Vec<PropResponse>,
}
impl MultiStatus {
    pub fn new() -> Self {
        Self {
            xmlns: "DAV:",
            response: Vec::new(),
        }
    }
}

#[derive(Facet, Debug)]
#[facet(rename = "response")]
pub struct PropResponse {
    href: String,
    propstat: PropStat,
}

#[derive(Facet, Debug)]
#[facet(rename = "propstat")]
struct PropStat {
    prop: Prop,
    #[facet(opaque, proxy = StatusCodeProxy)]
    status: StatusCode,
}

#[derive(Facet, Debug)]
#[facet(transparent)]
struct StatusCodeProxy(String);
impl TryFrom<&StatusCode> for StatusCodeProxy {
    type Error = Infallible;
    fn try_from(value: &StatusCode) -> Result<Self, Self::Error> {
        Ok(Self(format!(
            "HTTP/1.1 {} {}",
            value.0,
            value.default_reason_phrase()
        )))
    }
}
impl TryFrom<StatusCodeProxy> for StatusCode {
    type Error = &'static str;
    fn try_from(value: StatusCodeProxy) -> Result<Self, Self::Error> {
        delimited(("HTTP/1.1", space1::<_, ContextError>), dec_uint, rest)
            .map(Self)
            .parse(value.0.as_str())
            .map_err(|_| "invalid status code")
    }
}

#[derive(Facet, Debug)]
#[facet(rename = "prop")]
struct Prop {
    #[facet(xml::elements)]
    props: Vec<PropKind>,
}

#[derive(Facet, Debug)]
#[facet(rename_all = "lowercase")]
#[repr(u8)]
enum PropKind {
    CreationDate(String),
    DisplayName(String),
    GetContentLength(u64),
    GetContentType(String),
    GetEtag(String),
    GetLastModified(String),
    ResourceType { collection: Option<Empty> },
}

impl PropKind {
    fn clear_value(&mut self) {
        match self {
            Self::CreationDate(value)
            | Self::DisplayName(value)
            | Self::GetContentType(value)
            | Self::GetEtag(value)
            | Self::GetLastModified(value) => value.clear(),
            Self::GetContentLength(value) => *value = 0,
            Self::ResourceType { collection } => *collection = None,
        }
    }

    fn name(&self) -> &'static str {
        match self {
            Self::CreationDate(_) => "creationdate",
            Self::DisplayName(_) => "displayname",
            Self::GetContentLength(_) => "getcontentlength",
            Self::GetContentType(_) => "getcontenttype",
            Self::GetEtag(_) => "getetag",
            Self::GetLastModified(_) => "getlastmodified",
            Self::ResourceType { .. } => "resourcetype",
        }
    }
}

#[derive(Facet, Debug)]
struct Empty;

impl PropResponse {
    pub fn new(
        path: &Path,
        meta: &Metadata,
        base: &Path,
        include_etag: bool,
    ) -> Result<Self, Error> {
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
                    props: if meta.is_dir() {
                        vec![
                            PropKind::CreationDate(date_str(meta.created()?)),
                            PropKind::DisplayName(display),
                            PropKind::ResourceType {
                                collection: Some(Empty),
                            },
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
                            PropKind::GetEtag(if include_etag {
                                file_etag(meta)
                            } else {
                                String::new()
                            }),
                            PropKind::ResourceType { collection: None },
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
                .props
                .retain(|property| names.iter().any(|name| property.name() == name));
        }
        if names_only {
            for property in &mut self.propstat.prop.props {
                property.clear_value();
            }
        }
    }
}

#[cfg(test)]
mod test {
    use std::path::Path;

    use crate::multi_status::{
        MultiStatus, Prop, PropKind, PropResponse, PropStat, StatusCodeProxy,
    };
    use crate::util::{date_str, http_date_str};

    #[test]
    fn status_code_proxy() {
        for (input, expected) in [("HTTP/1.1 200 OK", 200), ("HTTP/1.1 404 Not Found", 404)] {
            let status = tiny_http::StatusCode::try_from(StatusCodeProxy(input.into())).unwrap();
            assert_eq!(status.0, expected);
        }

        for input in ["HTTP/1.0 200 OK", "HTTP/1.1 OK", "HTTP/1.1 65536 Overflow"] {
            assert!(tiny_http::StatusCode::try_from(StatusCodeProxy(input.into())).is_err());
        }
    }

    #[test]
    fn multistatus_resource_types() {
        for (collection, expected) in [
            (
                Some(super::Empty),
                "<resourcetype><collection></collection></resourcetype>",
            ),
            (None, "<resourcetype></resourcetype>"),
        ] {
            let mut multistatus = MultiStatus::new();
            multistatus.response.push(PropResponse {
                href: "/test".into(),
                propstat: PropStat {
                    prop: Prop {
                        props: vec![PropKind::ResourceType { collection }],
                    },
                    status: crate::status::OK,
                },
            });
            let xml = facet_xml::to_string(&multistatus).unwrap();
            assert_eq!(
                xml,
                format!(
                    "<multistatus xmlns=\"DAV:\"><response><href>/test</href><propstat><prop>{expected}</prop><status>HTTP/1.1 200 OK</status></propstat></response></multistatus>"
                )
            );

            multistatus.response[0].filter(None, true);
            let xml = facet_xml::to_string(&multistatus).unwrap();
            assert!(xml.contains("<resourcetype></resourcetype>"), "{xml}");
        }
    }

    #[test]
    fn prop_response() {
        let path = Path::new("src/");
        let base = Path::new("");
        let meta = path.metadata().unwrap();
        let res = PropResponse::new(path, &meta, base, true).unwrap();
        let xml = facet_xml::to_string(&res).unwrap();
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
                <resourcetype><collection></collection></resourcetype>\
                <getlastmodified>{mtime}</getlastmodified>\
                </prop><status>HTTP/1.1 200 OK</status></propstat></response>",
            )
        );
    }
}
