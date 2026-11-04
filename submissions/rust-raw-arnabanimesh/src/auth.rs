use std::time::{SystemTime, UNIX_EPOCH};

use aws_lc_rs::hmac;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use memchr::memchr;

/// base64url of `{"alg":"HS256","typ":"JWT"}`, the header every token we issue carries.
const JWT_HEADER_B64: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";

/// SPEC.md: `exp` is `now + 30 days`.
const TOKEN_TTL_SECS: i64 = 30 * 24 * 3600;

#[derive(Clone)]
pub struct JwtAuth {
    key: hmac::Key,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AuthOutcome {
    Anonymous,
    Authenticated(i64),
    Invalid,
}

impl JwtAuth {
    pub fn new(secret: &[u8]) -> Self {
        Self {
            key: hmac::Key::new(hmac::HMAC_SHA256, secret),
        }
    }

    #[inline]
    pub fn now_secs() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64
    }

    pub fn sign(&self, user_id: i64) -> String {
        let now = Self::now_secs();
        let exp = now + TOKEN_TTL_SECS;
        let payload_json = format!(r#"{{"sub":"{user_id}","iat":{now},"exp":{exp}}}"#);
        let payload_b64 = URL_SAFE_NO_PAD.encode(payload_json.as_bytes());

        let mut token = String::with_capacity(JWT_HEADER_B64.len() + 1 + payload_b64.len() + 1 + 43);
        token.push_str(JWT_HEADER_B64);
        token.push('.');
        token.push_str(&payload_b64);

        let sig = hmac::sign(&self.key, token.as_bytes());
        token.push('.');
        URL_SAFE_NO_PAD.encode_string(sig.as_ref(), &mut token);
        token
    }

    /// Verifies an `Authorization` header value (`Token <jwt>`).
    ///
    /// No header (or an empty one) is anonymous. Anything else must carry an HS256 token with a
    /// valid signature and an unexpired `exp`, otherwise the outcome is `Invalid` (-> 401).
    /// On success the token text is returned too, so `GET /api/user` can echo it back.
    #[inline]
    pub fn verify_header<'a>(&self, auth_header: Option<&'a [u8]>) -> (AuthOutcome, Option<&'a str>) {
        let raw = match auth_header {
            Some(h) if !h.is_empty() => h,
            _ => return (AuthOutcome::Anonymous, None),
        };

        let token_bytes = match raw.strip_prefix(b"Token ") {
            Some(t) => {
                let trimmed = t.trim_ascii();
                if trimmed.is_empty() {
                    return (AuthOutcome::Invalid, None);
                }
                trimmed
            }
            None => return (AuthOutcome::Invalid, None),
        };

        let token_str = match std::str::from_utf8(token_bytes) {
            Ok(s) => s,
            Err(_) => return (AuthOutcome::Invalid, None),
        };

        let dot1 = match memchr(b'.', token_bytes) {
            Some(i) => i,
            None => return (AuthOutcome::Invalid, None),
        };
        let rest = &token_bytes[dot1 + 1..];
        let dot2 = match memchr(b'.', rest) {
            Some(i) => i,
            None => return (AuthOutcome::Invalid, None),
        };

        let header_b64 = &token_bytes[..dot1];
        let payload_b64 = &rest[..dot2];
        let sig_b64 = &rest[dot2 + 1..];

        // Fast path: the exact header we issue. Otherwise decode it and require alg == HS256
        // (tokens minted elsewhere may order or space the header JSON differently).
        if header_b64 != JWT_HEADER_B64.as_bytes() {
            let mut hdr_buf = [0u8; 128];
            let hdr_len = match URL_SAFE_NO_PAD.decode_slice(header_b64, &mut hdr_buf) {
                Ok(n) => n,
                Err(_) => return (AuthOutcome::Invalid, None),
            };
            if !Self::header_is_hs256(&hdr_buf[..hdr_len]) {
                return (AuthOutcome::Invalid, None);
            }
        }

        let mut sig_buf = [0u8; 64];
        let sig_len = match URL_SAFE_NO_PAD.decode_slice(sig_b64, &mut sig_buf) {
            Ok(n) => n,
            Err(_) => return (AuthOutcome::Invalid, None),
        };
        let signed_input = &token_bytes[..dot1 + 1 + dot2];
        if hmac::verify(&self.key, signed_input, &sig_buf[..sig_len]).is_err() {
            return (AuthOutcome::Invalid, None);
        }

        let mut pay_buf = [0u8; 256];
        let pay_len = match URL_SAFE_NO_PAD.decode_slice(payload_b64, &mut pay_buf) {
            Ok(n) => n,
            Err(_) => return (AuthOutcome::Invalid, None),
        };
        let payload = &pay_buf[..pay_len];

        let exp = match Self::extract_int_claim(payload, b"\"exp\":") {
            Some(v) => v,
            None => return (AuthOutcome::Invalid, None),
        };
        if exp <= Self::now_secs() {
            return (AuthOutcome::Invalid, None);
        }

        let sub = match Self::extract_sub_id(payload) {
            Some(v) if v > 0 => v,
            _ => return (AuthOutcome::Invalid, None),
        };

        (AuthOutcome::Authenticated(sub), Some(token_str))
    }

    /// True if the decoded JOSE header has `"alg"` set to exactly `"HS256"`.
    fn header_is_hs256(hdr: &[u8]) -> bool {
        let key_pos = match memchr::memmem::find(hdr, b"\"alg\"") {
            Some(p) => p + 5,
            None => return false,
        };
        let is_ws = |b: u8| b == b' ' || b == b'\t' || b == b'\n' || b == b'\r';
        let mut i = key_pos;
        while i < hdr.len() && is_ws(hdr[i]) {
            i += 1;
        }
        if i >= hdr.len() || hdr[i] != b':' {
            return false;
        }
        i += 1;
        while i < hdr.len() && is_ws(hdr[i]) {
            i += 1;
        }
        hdr[i..].starts_with(b"\"HS256\"")
    }

    #[inline]
    fn extract_int_claim(buf: &[u8], key: &[u8]) -> Option<i64> {
        let pos = memchr::memmem::find(buf, key)? + key.len();
        let mut i = pos;
        while i < buf.len() && buf[i] == b' ' {
            i += 1;
        }
        let mut val: i64 = 0;
        let mut found = false;
        while i < buf.len() && buf[i].is_ascii_digit() {
            val = val.wrapping_mul(10).wrapping_add((buf[i] - b'0') as i64);
            i += 1;
            found = true;
        }
        found.then_some(val)
    }

    /// `sub` must be a JSON *string* of decimal digits (SPEC: "<user id as a decimal string>").
    /// A numeric `"sub": 100` is rejected, and so are empty, signed, non-digit and overflowing
    /// values.
    #[inline]
    fn extract_sub_id(buf: &[u8]) -> Option<i64> {
        let pos = memchr::memmem::find(buf, b"\"sub\":")? + 6;
        let mut i = pos;
        while i < buf.len() && matches!(buf[i], b' ' | b'\t' | b'\n' | b'\r') {
            i += 1;
        }
        if i >= buf.len() || buf[i] != b'"' {
            return None;
        }
        i += 1;
        let digits_start = i;
        let mut val: i64 = 0;
        while i < buf.len() && buf[i].is_ascii_digit() {
            val = val.checked_mul(10)?.checked_add((buf[i] - b'0') as i64)?;
            i += 1;
        }
        if i == digits_start || i >= buf.len() || buf[i] != b'"' {
            return None;
        }
        Some(val)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bearer(token: &str) -> Vec<u8> {
        format!("Token {token}").into_bytes()
    }

    #[test]
    fn sign_then_verify() {
        let auth = JwtAuth::new(b"multicore-server-challenge");
        let token = auth.sign(42);
        let hdr = bearer(&token);
        let (outcome, echoed) = auth.verify_header(Some(&hdr));
        assert_eq!(outcome, AuthOutcome::Authenticated(42));
        assert_eq!(echoed, Some(token.as_str()));
    }

    #[test]
    fn expiry_is_thirty_days() {
        let auth = JwtAuth::new(b"k");
        let token = auth.sign(1);
        let payload_b64 = token.split('.').nth(1).unwrap();
        let payload = URL_SAFE_NO_PAD.decode(payload_b64).unwrap();
        let exp = JwtAuth::extract_int_claim(&payload, b"\"exp\":").unwrap();
        let iat = JwtAuth::extract_int_claim(&payload, b"\"iat\":").unwrap();
        assert_eq!(exp - iat, 30 * 24 * 3600);
    }

    #[test]
    fn rejects_tampering_wrong_secret_and_garbage() {
        let a = JwtAuth::new(b"secret-a");
        let b = JwtAuth::new(b"secret-b");
        let token = a.sign(7);
        let hdr = bearer(&token);
        assert_eq!(b.verify_header(Some(&hdr)).0, AuthOutcome::Invalid);

        let mut tampered = token.clone().into_bytes();
        let n = tampered.len();
        tampered[n - 3] = if tampered[n - 3] == b'A' { b'B' } else { b'A' };
        let hdr = bearer(std::str::from_utf8(&tampered).unwrap());
        assert_eq!(a.verify_header(Some(&hdr)).0, AuthOutcome::Invalid);

        assert_eq!(a.verify_header(Some(b"Bearer x.y.z")).0, AuthOutcome::Invalid);
        assert_eq!(a.verify_header(Some(b"Token ")).0, AuthOutcome::Invalid);
        assert_eq!(a.verify_header(Some(b"Token not-a-jwt")).0, AuthOutcome::Invalid);
        assert_eq!(a.verify_header(None).0, AuthOutcome::Anonymous);
    }

    #[test]
    fn rejects_other_algs_and_expired_tokens() {
        let auth = JwtAuth::new(b"k");
        let sign = |header_json: &str, payload_json: &str| -> Vec<u8> {
            let h = URL_SAFE_NO_PAD.encode(header_json.as_bytes());
            let p = URL_SAFE_NO_PAD.encode(payload_json.as_bytes());
            let mut t = format!("{h}.{p}");
            let sig = hmac::sign(&auth.key, t.as_bytes());
            t.push('.');
            URL_SAFE_NO_PAD.encode_string(sig.as_ref(), &mut t);
            bearer(&t)
        };
        let far = JwtAuth::now_secs() + 1000;
        let past = JwtAuth::now_secs() - 5;

        // same signature scheme, other header shapes: HS256 with different key order is fine ...
        let ok = sign(r#"{"typ":"JWT","alg":"HS256"}"#, &format!(r#"{{"sub":"9","iat":1,"exp":{far}}}"#));
        assert_eq!(auth.verify_header(Some(&ok)).0, AuthOutcome::Authenticated(9));
        // ... but any other alg label is refused, even though the MAC is valid
        let bad_alg = sign(r#"{"alg":"HS384","typ":"JWT"}"#, &format!(r#"{{"sub":"9","iat":1,"exp":{far}}}"#));
        assert_eq!(auth.verify_header(Some(&bad_alg)).0, AuthOutcome::Invalid);
        let none_alg = sign(r#"{"alg":"none"}"#, &format!(r#"{{"sub":"9","iat":1,"exp":{far}}}"#));
        assert_eq!(auth.verify_header(Some(&none_alg)).0, AuthOutcome::Invalid);
        // expired
        let expired = sign(r#"{"alg":"HS256","typ":"JWT"}"#, &format!(r#"{{"sub":"9","iat":1,"exp":{past}}}"#));
        assert_eq!(auth.verify_header(Some(&expired)).0, AuthOutcome::Invalid);
    }

    #[test]
    fn sub_must_be_a_decimal_string() {
        let auth = JwtAuth::new(b"k");
        let far = JwtAuth::now_secs() + 1000;
        let check = |payload: String| -> AuthOutcome {
            let h = URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256","typ":"JWT"}"#);
            let p = URL_SAFE_NO_PAD.encode(payload.as_bytes());
            let mut t = format!("{h}.{p}");
            let sig = hmac::sign(&auth.key, t.as_bytes());
            t.push('.');
            URL_SAFE_NO_PAD.encode_string(sig.as_ref(), &mut t);
            auth.verify_header(Some(&bearer(&t))).0
        };

        // numeric sub (what Go's map-ordered claims look like): rejected
        assert_eq!(check(format!(r#"{{"exp":{far},"iat":1,"sub":100}}"#)), AuthOutcome::Invalid);
        // string sub is fine in any key order and with whitespace
        assert_eq!(check(format!(r#"{{"exp":{far},"iat":1,"sub":"100"}}"#)), AuthOutcome::Authenticated(100));
        assert_eq!(check(format!(r#"{{"sub": "100", "exp": {far}}}"#)), AuthOutcome::Authenticated(100));
        // not a positive decimal id
        for bad in [r#""sub":"abc""#, r#""sub":"""#, r#""sub":"-5""#, r#""sub":"12x""#,
                    r#""sub":"99999999999999999999""#, r#""sub":"0""#, r#""sub":null"#] {
            assert_eq!(check(format!(r#"{{"exp":{far},{bad}}}"#)), AuthOutcome::Invalid, "{bad}");
        }
        // missing sub
        assert_eq!(check(format!(r#"{{"exp":{far}}}"#)), AuthOutcome::Invalid);
    }
}