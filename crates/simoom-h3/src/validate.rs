//! Field section validation (RFC 9114 §4.2, §4.3; RFC 9110 §5.5).

use simoom_qpack::Field;

/// Facts learned while validating a header section.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Validated {
    pub content_length: Option<u64>,
    /// A 1xx response: more headers follow.
    pub informational: bool,
}

/// Returns the value of a pseudo-header or field.
pub fn pseudo<'a>(fields: &'a [Field], name: &[u8]) -> Option<&'a [u8]> {
    fields.iter().find(|f| f.name == name).map(|f| &f.value[..])
}

/// RFC 9110 token characters, lowercase only (RFC 9114 §4.2).
fn tchar_lower(c: u8) -> bool {
    c.is_ascii_lowercase() || c.is_ascii_digit() || b"!#$%&'*+-.^_`|~".contains(&c)
}

fn valid_name(n: &[u8]) -> bool {
    !n.is_empty() && n.iter().all(|&c| tchar_lower(c))
}

fn valid_method(m: &[u8]) -> bool {
    !m.is_empty() && m.iter().all(|&c| tchar_lower(c.to_ascii_lowercase()))
}

fn valid_value(v: &[u8]) -> bool {
    if let (Some(&a), Some(&b)) = (v.first(), v.last()) {
        if a == b' ' || a == b'\t' || b == b' ' || b == b'\t' {
            return false;
        }
    }
    v.iter().all(|&c| c != 0 && c != b'\r' && c != b'\n')
}

/// Checks the regular fields; returns the content length if present.
fn regular(fields: &[Field], start: usize) -> Result<Option<u64>, ()> {
    let mut cl: Option<u64> = None;
    for f in &fields[start..] {
        if f.name.first() == Some(&b':') || !valid_name(&f.name) || !valid_value(&f.value) {
            return Err(());
        }
        match &f.name[..] {
            b"connection" | b"keep-alive" | b"proxy-connection" | b"transfer-encoding" | b"upgrade" => return Err(()),
            b"te" if f.value != b"trailers" => return Err(()),
            b"content-length" => {
                if f.value.is_empty() || f.value.len() > 19 || !f.value.iter().all(u8::is_ascii_digit) {
                    return Err(());
                }
                let v: u64 = std::str::from_utf8(&f.value).map_err(|_| ())?.parse().map_err(|_| ())?;
                if cl.is_some_and(|c| c != v) {
                    return Err(());
                }
                cl = Some(v);
            }
            _ => {}
        }
    }
    Ok(cl)
}

/// Request header validation: pseudo-headers first, no duplicates, the required ones
/// present (CONNECT has only `:method` and `:authority`; extended CONNECT adds
/// `:protocol`, `:scheme` and `:path`).
pub fn validate_request(fields: &[Field]) -> Result<Validated, ()> {
    let (mut method, mut scheme, mut path, mut authority) = (None, None, None, None);
    let mut protocol = false;
    let mut i = 0;
    while i < fields.len() && fields[i].name.first() == Some(&b':') {
        let f = &fields[i];
        i += 1;
        if !valid_value(&f.value) {
            return Err(());
        }
        let slot = match &f.name[..] {
            b":method" => &mut method,
            b":scheme" => &mut scheme,
            b":path" => &mut path,
            b":authority" => &mut authority,
            b":protocol" => {
                if protocol {
                    return Err(());
                }
                protocol = true;
                continue;
            }
            _ => return Err(()),
        };
        if slot.is_some() {
            return Err(());
        }
        *slot = Some(&f.value[..]);
    }
    let method: &[u8] = method.ok_or(())?;
    if !valid_method(method) {
        return Err(());
    }
    let connect = method == b"CONNECT";
    if connect && !protocol {
        if scheme.is_some() || path.is_some() || authority.is_none_or(|a| a.is_empty()) {
            return Err(());
        }
    } else {
        if scheme.is_none_or(|s| s.is_empty()) || path.is_none_or(|p| p.is_empty()) {
            return Err(());
        }
        if protocol && !connect {
            return Err(());
        }
    }
    let content_length = regular(fields, i)?;
    Ok(Validated { content_length, informational: false })
}

/// Response header validation: exactly one three-digit `:status`, no other pseudo-header.
pub fn validate_response(fields: &[Field]) -> Result<Validated, ()> {
    let mut status = None;
    let mut i = 0;
    while i < fields.len() && fields[i].name.first() == Some(&b':') {
        if fields[i].name != b":status" || status.is_some() {
            return Err(());
        }
        status = Some(&fields[i].value[..]);
        i += 1;
    }
    let s = status.ok_or(())?;
    if s.len() != 3 || !s.iter().all(u8::is_ascii_digit) || s[0] == b'0' {
        return Err(());
    }
    let content_length = regular(fields, i)?;
    Ok(Validated { content_length, informational: s[0] == b'1' })
}

/// Trailers carry no pseudo-headers.
pub fn validate_trailers(fields: &[Field]) -> Result<(), ()> {
    regular(fields, 0).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(list: &[(&str, &str)]) -> Vec<Field> {
        list.iter().map(|(n, v)| Field::new(n.as_bytes(), v.as_bytes())).collect()
    }

    #[test]
    fn request_rules() {
        let ok = f(&[(":method", "GET"), (":scheme", "https"), (":authority", "x"), (":path", "/"), ("accept", "*/*")]);
        assert!(validate_request(&ok).is_ok());
        let bad = [
            f(&[(":method", "GET"), (":path", "/")]),
            f(&[(":method", "GET"), (":scheme", "https"), (":path", "")]),
            f(&[(":method", "GET"), (":method", "GET"), (":scheme", "h"), (":path", "/")]),
            f(&[(":method", "GET"), ("a", "b"), (":scheme", "h"), (":path", "/")]),
            f(&[(":method", "GET"), (":scheme", "h"), (":path", "/"), (":status", "200")]),
            f(&[(":method", "GET"), (":scheme", "h"), (":path", "/"), ("Upper", "x")]),
            f(&[(":method", "GET"), (":scheme", "h"), (":path", "/"), ("connection", "close")]),
            f(&[(":method", "GET"), (":scheme", "h"), (":path", "/"), ("te", "gzip")]),
            f(&[(":method", "GET"), (":scheme", "h"), (":path", "/"), ("x", " lead")]),
            f(&[(":method", "GET"), (":scheme", "h"), (":path", "/"), ("x", "a\r\nb")]),
            f(&[(":method", "GET"), (":scheme", "h"), (":path", "/"), ("content-length", "1x")]),
            f(&[(":method", "GET"), (":scheme", "h"), (":path", "/"), ("content-length", "1"), ("content-length", "2")]),
            f(&[(":method", "CONNECT"), (":authority", "x"), (":path", "/")]),
            f(&[(":method", "GET"), (":protocol", "websocket"), (":scheme", "h"), (":path", "/")]),
            f(&[(":method", "G T"), (":scheme", "h"), (":path", "/")]),
        ];
        for b in &bad {
            assert!(validate_request(b).is_err(), "{b:?}");
        }
        assert!(validate_request(&f(&[(":method", "CONNECT"), (":authority", "x:443")])).is_ok());
        let ws = f(&[(":method", "CONNECT"), (":protocol", "websocket"), (":scheme", "https"), (":path", "/c"), (":authority", "x")]);
        assert!(validate_request(&ws).is_ok());
        let cl = f(&[(":method", "POST"), (":scheme", "h"), (":path", "/"), ("content-length", "12"), ("te", "trailers")]);
        assert_eq!(validate_request(&cl).unwrap().content_length, Some(12));
    }

    #[test]
    fn response_and_trailer_rules() {
        assert!(validate_response(&f(&[(":status", "200")])).is_ok());
        assert!(validate_response(&f(&[(":status", "103")])).unwrap().informational);
        assert!(validate_response(&f(&[(":status", "20")])).is_err());
        assert!(validate_response(&f(&[(":status", "200"), (":status", "200")])).is_err());
        assert!(validate_response(&f(&[(":path", "/")])).is_err());
        assert!(validate_trailers(&f(&[("grpc-status", "0")])).is_ok());
        assert!(validate_trailers(&f(&[(":status", "200")])).is_err());
    }
}
