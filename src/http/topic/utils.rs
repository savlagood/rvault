pub fn is_valid_name(input: &str) -> bool {
    input.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}
