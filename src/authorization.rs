use std::collections::BTreeMap;

use axum::{
    extract::Request,
    http::{HeaderMap, StatusCode},
};
use base64::prelude::*;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use tracing::{Level, debug, span};

const EMULATOR_DEFAULT_ACCOUNT_KEY: &str =
    "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==";

pub enum AuthorizationError {
    Unauthorized,
    InvalidHeader,
    NotApplicable,
}

pub trait AuthorizationScheme {
    async fn authorize(&self, request: &Request) -> Result<(), AuthorizationError>;
}

pub struct SharedKeyAuthorization;

impl SharedKeyAuthorization {
    /// Canonicalizes headers prefixed with `x-ms-`.
    fn canonicalize_ms_headers(headers: &HeaderMap) -> String {
        // Use a BTreeMap to sort headers lexicographically by name
        let mut ms_headers = BTreeMap::new();

        for (key, value) in headers.iter() {
            let key_str = key.as_str().to_lowercase();

            if key_str.starts_with("x-ms-") {
                if let Ok(val) = value.to_str() {
                    ms_headers.insert(key_str, val.to_string());
                }
            }
        }

        let mut result = String::new();

        for (key, value) in ms_headers.iter() {
            result.push_str(&format!("{}:{}\n", key, value));
        }

        result
    }

    /// Canonicalizes the resource string.
    fn canonicalize_resource(uri: &str, account_name: &str) -> String {
        // Parse the URI to extract path and query.
        let uri_parts: Vec<&str> = uri.split('?').collect();
        let path = uri_parts[0];

        let mut result = format!("/{}/{}", account_name, path.trim_start_matches('/'));

        // If there are query parameters, canonicalize them.
        if uri_parts.len() > 1 {
            let query = uri_parts[1];
            let mut params = BTreeMap::new();

            for param in query.split('&') {
                if let Some((key, value)) = param.split_once('=') {
                    params.insert(key.to_lowercase(), value);
                } else {
                    params.insert(param.to_lowercase(), "");
                }
            }

            for (key, value) in params {
                if !value.is_empty() {
                    result.push_str(&format!("\n{}:{}", key, value));
                } else {
                    result.push_str(&format!("\n{}", key));
                }
            }
        }

        result
    }

    // Function to validate the signature
    fn verify_signature(string_to_sign: &str, provided_signature: &str) -> bool {
        // For the emulator, we use the default key
        let decoded_key = BASE64_STANDARD
            .decode(EMULATOR_DEFAULT_ACCOUNT_KEY)
            .expect("account key should be base64 decodable");

        let mut hmac = Hmac::<Sha256>::new_from_slice(&decoded_key).unwrap();
        hmac.update(string_to_sign.as_bytes());

        // Get the result and compare
        let computed_signature = BASE64_STANDARD.encode(hmac.finalize().into_bytes());
        provided_signature == computed_signature
    }

    /// Gets a header value as a string, or an empty string if the header is not present.
    fn get_header_string_allow_empty(headers: &HeaderMap, key: &str) -> String {
        if let Some(header) = headers.get(key) {
            if let Ok(header_value) = header.to_str() {
                return header_value.to_string();
            }
        }

        String::new()
    }
}

impl AuthorizationScheme for SharedKeyAuthorization {
    async fn authorize(&self, request: &Request) -> Result<(), AuthorizationError> {
        let span = span!(Level::DEBUG, "SharedKeyAuthorization");
        let _enter = span.enter();

        debug!("Starting shared key authorization");

        let headers = request.headers();
        let auth_header = headers.get("Authorization");

        if auth_header.is_none() {
            return Err(AuthorizationError::NotApplicable);
        }

        let auth_header = match auth_header.unwrap().to_str() {
            Ok(header) => header,
            Err(_) => {
                return Err(AuthorizationError::InvalidHeader);
            }
        };

        if !auth_header.starts_with("SharedKey ") {
            debug!("Authorization header does not start with 'SharedKey'");
            return Err(AuthorizationError::NotApplicable);
        }

        // Parse the auth header to extract the authentication scheme, account name, and signature.
        // Format: "[SharedKey|SharedKeyLite] <AccountName>:<Signature>"
        let (auth_scheme, account_and_signature) = match auth_header.split_once(' ') {
            Some(parts) => parts,
            None => return Err(StatusCode::FORBIDDEN),
        };

        // Ensure the auth scheme is either "SharedKey" or "SharedKeyLite".
        if auth_scheme != "SharedKey" && auth_scheme != "SharedKeyLite" {
            tracing::debug!("Invalid auth scheme: {}", auth_scheme);
            return Err(StatusCode::FORBIDDEN);
        }

        // Extract the account name and signature.
        let (account_name, signature) = match account_and_signature.split_once(':') {
            Some(parts) => parts,
            None => return Err(StatusCode::FORBIDDEN),
        };

        // TODO: check if account exists - 404?
        if account_name.is_empty() {
            tracing::debug!("Account name is empty");
            return Err(StatusCode::FORBIDDEN);
        }

        let headers = request.headers();
        let canonicalized_headers = canonicalize_ms_headers(headers);
        let canonicalized_resource =
            canonicalize_resource(&request.uri().to_string(), account_name);

        // TODO: possibly use + to append string instead of format.
        // TODO: we need to use x-ms-date val if it exists.
        let generated_signature = format!(
            "{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}{}",
            request.method(),
            get_header_string_allow_empty(headers, "Content-Encoding"),
            get_header_string_allow_empty(headers, "Content-Language"),
            get_header_string_allow_empty(headers, "Content-Length"),
            get_header_string_allow_empty(headers, "Content-MD5"),
            get_header_string_allow_empty(headers, "Content-Type"),
            get_header_string_allow_empty(headers, "Date"),
            get_header_string_allow_empty(headers, "If-Modified-Since"),
            get_header_string_allow_empty(headers, "If-Match"),
            get_header_string_allow_empty(headers, "If-None-Match"),
            get_header_string_allow_empty(headers, "If-Unmodified-Since"),
            get_header_string_allow_empty(headers, "Range"),
            canonicalized_headers,
            canonicalized_resource
        );

        if !verify_signature(&generated_signature, signature) {
            tracing::debug!("Signature verification failed");
            return Err(StatusCode::FORBIDDEN);
        } else {
            tracing::debug!("Signature verification succeeded");
        }

        Ok(())
    }
}
