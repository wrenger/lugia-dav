use std::fs::{self, Metadata};
use std::io;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use tiny_http::{Header, Method, StatusCode};
use url::Url;
use winnow::ascii::{Caseless, space0};
use winnow::combinator::{alt, delimited, opt, preceded, repeat, separated, terminated};
use winnow::stream::AsChar;
use winnow::token::take_while;
use winnow::{ModalResult, Parser};

use crate::{dav::Error, status};

#[derive(Debug, Clone)]
pub struct ResourceState {
    pub exists: bool,
    pub etag: Option<String>,
    pub modified: Option<SystemTime>,
}

impl ResourceState {
    pub fn read(path: &Path) -> Result<Self, Error> {
        let metadata = match fs::metadata(path) {
            Ok(metadata) => metadata,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Ok(Self {
                    exists: false,
                    etag: None,
                    modified: None,
                });
            }
            Err(e) => return Err(e.into()),
        };
        if !metadata.is_file() {
            return Ok(Self {
                exists: true,
                etag: None,
                modified: None,
            });
        }

        Ok(Self {
            exists: true,
            etag: Some(file_etag(&metadata)),
            modified: Some(metadata.modified()?),
        })
    }

    fn modified(&self) -> Option<u64> {
        if self.exists {
            self.modified.map(|t| {
                t.duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or_default()
            })
        } else {
            None
        }
    }

    fn current_tag(&self) -> Option<EntityTag<'_>> {
        if self.exists {
            entity_tag.parse(self.etag.as_deref()?).ok()
        } else {
            None
        }
    }

    fn matches_tag(&self, tag: &EntityTag<'_>, strong: bool) -> bool {
        self.current_tag().is_some_and(|current| {
            current.opaque == tag.opaque && (!strong || (!current.weak && !tag.weak))
        })
    }

    fn matches_tags(&self, list: &TagList<'_>, strong: bool) -> bool {
        match list {
            TagList::Any => self.exists,
            TagList::Tags(tags) => tags.iter().any(|tag| self.matches_tag(tag, strong)),
        }
    }

    fn matches(&self, condition: &Condition<'_>) -> bool {
        match condition {
            Condition::Token(_) => false, // No locking for now
            Condition::Tag(tag) => self.matches_tag(tag, true),
        }
    }
}

pub fn file_etag(meta: &Metadata) -> String {
    let mtime = meta
        .modified()
        .ok()
        .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    format!("\"{mtime:x}-{:x}\"", meta.len())
}

#[derive(Debug)]
struct EntityTag<'a> {
    weak: bool,
    opaque: &'a str,
}
impl<'a> EntityTag<'a> {
    fn new(weak: bool, opaque: &'a str) -> Self {
        Self { weak, opaque }
    }
}

fn entity_tag<'a>(input: &mut &'a str) -> ModalResult<EntityTag<'a>> {
    (
        opt("W/"),
        delimited(
            '"',
            take_while(0.., |c: char| c >= '\u{21}' && c != '\u{7f}' && c != '"'),
            '"',
        ),
    )
        .map(|(weak, opaque)| EntityTag::new(weak.is_some(), opaque))
        .parse_next(input)
}

fn coded_url<'a>(input: &mut &'a str) -> ModalResult<&'a str> {
    delimited(
        '<',
        take_while(1.., |c: char| c.is_ascii_graphic() && c != '<' && c != '>'),
        '>',
    )
    .parse_next(input)
}

enum TagList<'a> {
    Any,
    Tags(Vec<EntityTag<'a>>),
}
fn tag_list(value: &str) -> Result<TagList<'_>, Error> {
    delimited(
        space0,
        alt((
            "*".map(|_| TagList::Any),
            separated(1.., opt(entity_tag), (space0, ',', space0))
                .map(|tags: Vec<_>| TagList::Tags(tags.into_iter().flatten().collect())),
        )),
        space0,
    )
    .parse(value)
    .map_err(|_| status::BAD_REQUEST.into())
}

#[derive(Debug)]
enum Condition<'a> {
    Token(#[allow(dead_code)] &'a str),
    Tag(EntityTag<'a>),
}

#[derive(Debug)]
struct Test<'a> {
    not: bool,
    condition: Condition<'a>,
}
impl<'a> Test<'a> {
    fn new(not: bool, condition: Condition<'a>) -> Self {
        Self { not, condition }
    }
}

#[derive(Debug)]
struct Group<'a> {
    resource: Option<&'a str>,
    lists: Vec<Vec<Test<'a>>>,
}
impl<'a> Group<'a> {
    fn new(resource: Option<&'a str>, lists: Vec<Vec<Test<'a>>>) -> Self {
        Self { resource, lists }
    }
}

fn uri_characters(input: &mut &str) -> ModalResult<()> {
    repeat(
        0..,
        alt((
            take_while(1.., |c: char| {
                c.is_ascii_alphanumeric() || "-._~:/?#[]@!$&'()*+,;=".contains(c)
            }),
            ('%', take_while(2, AsChar::is_hex_digit)).take(),
        )),
    )
    .parse_next(input)
}

fn uri_chars(s: &str) -> bool {
    uri_characters.parse(s).is_ok()
}
fn absolute_uri(s: &str) -> bool {
    uri_chars(s) && Url::parse(s).is_ok()
}
fn resource_tag(s: &str) -> bool {
    (s.starts_with('/') && !s.starts_with("//") && !s.contains('#') && uri_chars(s))
        || absolute_uri(s)
}
fn condition<'a>(input: &mut &'a str) -> ModalResult<Test<'a>> {
    (
        opt(terminated(Caseless("Not"), space0)),
        alt((
            coded_url.verify(absolute_uri).map(Condition::Token),
            delimited('[', entity_tag, ']').map(Condition::Tag),
        )),
    )
        .map(|(not, condition)| Test::new(not.is_some(), condition))
        .parse_next(input)
}

fn condition_list<'a>(input: &mut &'a str) -> ModalResult<Vec<Test<'a>>> {
    delimited(
        '(',
        preceded(space0, repeat(1.., terminated(condition, space0))),
        ')',
    )
    .parse_next(input)
}

fn tagged_group<'a>(input: &mut &'a str) -> ModalResult<Group<'a>> {
    (
        terminated(coded_url.verify(resource_tag), space0),
        repeat(1.., terminated(condition_list, space0)),
    )
        .map(|(resource, lists)| Group::new(Some(resource), lists))
        .parse_next(input)
}

fn dav_if(value: &str) -> Result<Vec<Group<'_>>, Error> {
    preceded(
        space0,
        alt((
            repeat(1.., tagged_group),
            repeat(1.., terminated(condition_list, space0))
                .map(|lists| vec![Group::new(None, lists)]),
        )),
    )
    .parse(value)
    .map_err(|_| status::BAD_REQUEST.into())
}

fn headers<'a>(headers: &'a [Header], name: &'static str) -> Vec<&'a str> {
    headers
        .iter()
        .filter(|h| h.field.equiv(name))
        .map(|h| h.value.as_str())
        .collect()
}
fn date(value: &str) -> Option<u64> {
    httpdate::parse_http_date(value.trim()).ok().map(|t| {
        t.duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or_default()
    })
}
fn single<T>(f: impl Fn(&str) -> Option<T>, values: &[&str]) -> Option<T> {
    if values.len() == 1 {
        f(values[0])
    } else {
        None
    }
}

pub fn evaluate(
    method: &Method,
    request_headers: &[Header],
    state: &ResourceState,
    mut resolve: impl FnMut(&str) -> Result<ResourceState, Error>,
) -> Result<Option<StatusCode>, Error> {
    let dav = headers(request_headers, "If");
    if dav.len() > 1 {
        return Err(status::BAD_REQUEST.into());
    }
    let parsed_dav = dav.first().map(|value| dav_if(value)).transpose()?;

    let if_match = headers(request_headers, "If-Match");
    let match_value = if_match.join(",");
    let match_list = if !if_match.is_empty() {
        Some(tag_list(&match_value)?)
    } else {
        None
    };

    let if_none = headers(request_headers, "If-None-Match");
    let none_value = if_none.join(",");
    let none_list = if !if_none.is_empty() {
        Some(tag_list(&none_value)?)
    } else {
        None
    };

    if let Some(groups) = parsed_dav {
        let mut matched = false;
        for group in groups {
            let resolved;
            let target = if let Some(resource) = group.resource {
                resolved = resolve(resource)?;
                &resolved
            } else {
                state
            };
            if group.lists.iter().any(|list| {
                list.iter()
                    .all(|test| target.matches(&test.condition) != test.not)
            }) {
                matched = true;
            }
        }
        if !matched {
            return Ok(Some(status::PRECONDITION_FAILED));
        }
    }
    if let Some(list) = match_list {
        if !state.matches_tags(&list, true) {
            return Ok(Some(status::PRECONDITION_FAILED));
        }
    } else if let (Some(m), Some(d)) = (
        state.modified(),
        single(date, &headers(request_headers, "If-Unmodified-Since")),
    ) && m > d
    {
        return Ok(Some(status::PRECONDITION_FAILED));
    }
    let safe = matches!(method, Method::Get | Method::Head);
    if let Some(list) = none_list {
        if state.matches_tags(&list, false) {
            return Ok(Some(if safe {
                status::NOT_MODIFIED
            } else {
                status::PRECONDITION_FAILED
            }));
        }
    } else if safe
        && let (Some(m), Some(d)) = (
            state.modified(),
            single(date, &headers(request_headers, "If-Modified-Since")),
        )
        && m <= d
    {
        return Ok(Some(status::NOT_MODIFIED));
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs::File, time::Duration};

    fn state(exists: bool, etag: Option<&str>, time: Option<u64>) -> ResourceState {
        ResourceState {
            exists,
            etag: etag.map(str::to_owned),
            modified: time.map(|s| UNIX_EPOCH + Duration::from_secs(s)),
        }
    }
    fn check(
        method: Method,
        values: &[(&str, &str)],
        target: &ResourceState,
    ) -> Result<Option<StatusCode>, Error> {
        let headers: Vec<_> = values
            .iter()
            .map(|(k, v)| Header::from_bytes(*k, *v).unwrap())
            .collect();
        evaluate(&method, &headers, target, |tag| {
            Ok(if tag == "/yes" {
                state(true, Some("\"yes\""), None)
            } else {
                state(false, None, None)
            })
        })
    }
    fn code(result: Result<Option<StatusCode>, Error>) -> Option<u16> {
        result.unwrap().map(|s| s.0)
    }

    #[test]
    fn resource_state_reads_files_and_directories() {
        let dir = std::env::temp_dir().join(format!("lugia-conditional-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("file");
        std::fs::write(&path, b"abc").unwrap();
        let file = ResourceState::read(&path).unwrap();
        let etag = file.etag.as_deref().unwrap();
        assert!(etag.starts_with('"') && etag.ends_with('"'), "{etag}");
        assert!(file.modified.is_some());
        let collection = ResourceState::read(&dir).unwrap();
        assert!(collection.exists && collection.etag.is_none() && collection.modified.is_none());
        assert!(!ResourceState::read(&dir.join("missing")).unwrap().exists);

        let mtime = UNIX_EPOCH;
        File::open(&path).unwrap().set_modified(mtime).unwrap();
        let etag = ResourceState::read(&path).unwrap().etag;
        File::open(&path).unwrap().set_modified(mtime).unwrap();
        assert_eq!(ResourceState::read(&path).unwrap().etag, etag);
        File::open(&path)
            .unwrap()
            .set_modified(mtime + Duration::from_secs(1))
            .unwrap();
        assert_ne!(ResourceState::read(&path).unwrap().etag, etag);
        std::fs::write(&path, b"abcd").unwrap();
        File::open(&path)
            .unwrap()
            .set_modified(mtime + Duration::from_secs(1))
            .unwrap();
        assert_ne!(ResourceState::read(&path).unwrap().etag, etag);
        std::fs::remove_file(path).unwrap();
        std::fs::remove_dir(dir).unwrap();
    }
    #[test]
    fn http_tags_and_wildcards() {
        let file = state(true, Some("\"a,b]\""), None);
        assert_eq!(
            code(check(
                Method::Get,
                &[("If-None-Match", "W/\"a,b]\"")],
                &file
            )),
            Some(304)
        );
        assert_eq!(
            code(check(Method::Put, &[("If-Match", "W/\"a,b]\"")], &file)),
            Some(412)
        );
        assert_eq!(
            code(check(
                Method::Put,
                &[("If-Match", "\"no\""), ("If-Match", "\"a,b]\"")],
                &file
            )),
            None
        );
        for target in [state(false, None, None), state(true, None, None)] {
            assert_eq!(
                code(check(Method::Put, &[("If-Match", "*")], &target)),
                if target.exists { None } else { Some(412) }
            );
            assert_eq!(
                code(check(Method::Get, &[("If-None-Match", "*")], &target)),
                if target.exists { Some(304) } else { None }
            );
        }
        assert_eq!(
            code(check(
                Method::Put,
                &[("If-None-Match", "W/\"a,b]\"")],
                &file
            )),
            Some(412)
        );
        let unicode = state(true, Some("\"é\""), None);
        assert_eq!(
            code(check(Method::Get, &[("If-Match", "\"other\"")], &unicode)),
            Some(412)
        );
        assert!(check(Method::Get, &[("If-Match", "*, \"x\"")], &file).is_err());
        assert_eq!(
            code(check(Method::Get, &[("If-None-Match", "\"x\", ")], &file)),
            None
        );
    }
    #[test]
    fn http_tag_lists_ignore_empty_members() {
        let file = state(true, Some("\"current\""), None);
        for value in [
            ", \"current\"",
            "\"current\",",
            ",, \"old\", ,\t\"current\", ,",
        ] {
            assert_eq!(
                code(check(Method::Put, &[("If-Match", value)], &file)),
                None
            );
            assert_eq!(
                code(check(Method::Get, &[("If-None-Match", value)], &file)),
                Some(304)
            );
        }
        for value in ["", " , ,\t", ", \"old\",,"] {
            assert_eq!(
                code(check(Method::Put, &[("If-Match", value)], &file)),
                Some(412)
            );
            assert_eq!(
                code(check(Method::Get, &[("If-None-Match", value)], &file)),
                None
            );
        }
    }

    #[test]
    fn http_dates_and_precedence() {
        let file = state(true, Some("\"x\""), Some(100));
        let old = "Thu, 01 Jan 1970 00:00:30 GMT";
        let new = "Thu, 01 Jan 1970 00:02:00 GMT";
        assert_eq!(
            code(check(Method::Put, &[("If-Unmodified-Since", old)], &file)),
            Some(412)
        );
        assert_eq!(
            code(check(
                Method::Put,
                &[("If-Match", "\"x\""), ("If-Unmodified-Since", old)],
                &file
            )),
            None
        );
        assert_eq!(
            code(check(Method::Get, &[("If-Modified-Since", new)], &file)),
            Some(304)
        );
        assert_eq!(
            code(check(
                Method::Get,
                &[("If-None-Match", "\"other\""), ("If-Modified-Since", new)],
                &file
            )),
            None
        );
        assert_eq!(
            code(check(Method::Put, &[("If-Modified-Since", new)], &file)),
            None
        );
        assert_eq!(
            code(check(
                Method::Get,
                &[("If-Modified-Since", new), ("If-Modified-Since", new)],
                &file
            )),
            None
        );
        assert_eq!(
            code(check(
                Method::Get,
                &[("If-Modified-Since", "invalid")],
                &file
            )),
            None
        );
    }
    #[test]
    fn obsolete_dates_and_subsecond_precision() {
        let date = "Sun, 06 Nov 1994 08:49:37 GMT";
        let instant = httpdate::parse_http_date(date).unwrap();
        let mut file = state(true, Some("\"x\""), None);
        file.modified = Some(instant + Duration::from_millis(999));
        for value in [
            date,
            "Sunday, 06-Nov-94 08:49:37 GMT",
            "Sun Nov  6 08:49:37 1994",
        ] {
            assert_eq!(
                code(check(Method::Get, &[("If-Modified-Since", value)], &file)),
                Some(304),
                "{value}"
            );
            assert_eq!(
                code(check(Method::Put, &[("If-Unmodified-Since", value)], &file)),
                None,
                "{value}"
            );
        }
    }
    #[test]
    fn http_and_dav_conditions_both_apply() {
        let file = state(true, Some("\"x\""), None);
        for (dav, http, expected) in [
            ("([\"x\"])", "\"x\"", None),
            ("([\"x\"])", "\"other\"", Some(412)),
            ("([\"other\"])", "\"x\"", Some(412)),
            ("([\"other\"])", "\"other\"", Some(412)),
        ] {
            assert_eq!(
                code(check(
                    Method::Put,
                    &[("If", dav), ("If-Match", http)],
                    &file
                )),
                expected
            );
        }
    }
    #[test]
    fn dav_boolean_and_tagged() {
        let file = state(true, Some("\"a,b]\""), None);
        for (value, expected) in [
            ("([\"a,b]\"])", None),
            ("([W/\"a,b]\"])", Some(412)),
            ("(<urn:fake>)", Some(412)),
            ("(Not <urn:fake>)", None),
            ("([\"wrong\"]) ([\"a,b]\"])", None),
            ("([\"a,b]\"] <urn:fake>)", Some(412)),
            ("</missing> ([\"x\"]) </yes> ([\"yes\"])", None),
            ("</missing> (Not [\"x\"])", None),
        ] {
            assert_eq!(
                code(check(Method::Get, &[("If", value)], &file)),
                expected,
                "{value}"
            );
        }
    }
    #[test]
    fn dav_negation_is_case_insensitive() {
        let file = state(true, Some("\"current\""), None);
        for keyword in ["Not", "not", "NOT", "nOt"] {
            for (condition, expected) in [
                ("<DAV:no-lock>", None),
                ("[\"other\"]", None),
                ("[\"current\"]", Some(412)),
            ] {
                let value = format!("({keyword} {condition})");
                assert_eq!(
                    code(check(Method::Put, &[("If", &value)], &file)),
                    expected,
                    "{value}"
                );
            }
        }
    }

    #[test]
    fn parser_preserves_quoted_tags_and_whitespace() {
        let file = state(true, Some("\"a,b]\""), None);
        for value in ["\t W/\"a,b]\" \t", " \"other\" ,\t\"a,b]\" "] {
            assert_eq!(
                code(check(Method::Get, &[("If-None-Match", value)], &file)),
                Some(304),
                "{value}"
            );
        }
        for value in [
            "\t( Not <DAV:no-lock> [\"a,b]\"] )\t",
            " </a%20b> (Not [\"missing\"])\t",
            "<https://example.com/a%5Db> (Not <urn:fake>)",
        ] {
            assert_eq!(
                code(check(Method::Put, &[("If", value)], &file)),
                None,
                "{value}"
            );
        }
        let tag = entity_tag.parse("W/\"é,]\"").unwrap();
        assert!(tag.weak);
        assert_eq!(tag.opaque, "é,]");
        assert_eq!(entity_tag.parse("\"\"").unwrap().opaque, "");
    }

    #[test]
    fn parsers_reject_trailing_input_and_invalid_uri_encoding() {
        for value in [
            "* trailing",
            "\"x\" trailing",
            "\"x\", *",
            ", *",
            "*,",
            "\"x\", invalid",
            "\"x y\"",
        ] {
            assert!(tag_list(value).is_err(), "{value}");
        }
        for value in [
            "([\"x\"]) trailing",
            "</yes> ([\"yes\"]) </missing>",
            "</yes> ([\"yes\"]) ()",
            "</a%> (Not <urn:fake>)",
            "</a%2> (Not <urn:fake>)",
            "</a%GG> (Not <urn:fake>)",
            "(Not <urn:bad%GG>)",
            "(Not <>)",
            "([\"x\"]\n)",
            "([\"x\" ])",
        ] {
            assert!(dav_if(value).is_err(), "{value}");
        }
    }

    #[test]
    fn malformed_dav_is_not_hidden() {
        let file = state(true, Some("\"x\""), None);
        for value in [
            "",
            "()",
            "([\"x\"]) ()",
            "([\"x\"]) </yes> ([\"yes\"])",
            "<relative> ([\"x\"])",
            "(<not a uri>)",
            "([ \"x\"])",
            "((<urn:x>))",
            "([\"x\"]",
            "(<relative>)",
        ] {
            assert!(
                check(Method::Get, &[("If", value)], &file).is_err(),
                "{value}"
            );
        }
        assert!(
            check(
                Method::Get,
                &[("If", "([\"x\"])"), ("If", "([\"x\"])")],
                &file
            )
            .is_err()
        );
        assert!(
            check(
                Method::Get,
                &[("If-Match", "\"wrong\""), ("If", "()")],
                &file
            )
            .is_err()
        );
    }
}
