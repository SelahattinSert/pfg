pub fn mask_sensitive_value(value: &str) -> String {
    let char_count = value.chars().count();
    if char_count <= 4 {
        "****".to_string()
    } else {
        let prefix: String = value.chars().take(2).collect();
        format!("{}***", prefix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_masking() {
        assert_eq!(mask_sensitive_value("123"), "****");
        assert_eq!(mask_sensitive_value("1234"), "****");
        assert_eq!(mask_sensitive_value("Secret author"), "Se***");
    }
}
