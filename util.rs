use base64::{engine::general_purpose, Engine as _};

/// Base64 URL-safe without padding
pub fn base64url(bytes: &[u8]) -> String {
    general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}
