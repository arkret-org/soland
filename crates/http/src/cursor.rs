use crate::error::ErrorCode;

pub const CURSOR_HANDLE_MIN_LENGTH: usize = 22;

pub fn validate_cursor_handle(handle: &str) -> Result<(), (ErrorCode, &'static str)> {
    if handle.len() < CURSOR_HANDLE_MIN_LENGTH {
        return Err((
            ErrorCode::CursorIntegrityInvalid,
            "cursor handle MUST be at least 22 base64url characters (>=128-bit entropy)",
        ));
    }
    if !handle
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
    {
        return Err((
            ErrorCode::CursorIntegrityInvalid,
            "cursor handle MUST be base64url (no padding)",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursor_handle_requires_128_bits_of_base64url_entropy() {
        assert!(validate_cursor_handle(&"a".repeat(22)).is_ok());
        assert!(validate_cursor_handle(&"a".repeat(21)).is_err());
        assert!(validate_cursor_handle("aaaaaaaaaaaaaaaaaaaaa=").is_err());
    }
}
