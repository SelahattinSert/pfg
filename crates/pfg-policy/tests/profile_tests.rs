use pfg_policy::CleanProfile;

#[test]
fn test_clean_profile_default() {
    assert_eq!(CleanProfile::default(), CleanProfile::Balanced);
}

#[test]
fn test_clean_profile_serde_serialize() {
    let balanced = serde_json::to_string(&CleanProfile::Balanced).unwrap();
    assert_eq!(balanced, r#""balanced""#);

    let strict = serde_json::to_string(&CleanProfile::Strict).unwrap();
    assert_eq!(strict, r#""strict""#);
}

#[test]
fn test_clean_profile_serde_deserialize() {
    let balanced: CleanProfile = serde_json::from_str(r#""balanced""#).unwrap();
    assert_eq!(balanced, CleanProfile::Balanced);

    let strict: CleanProfile = serde_json::from_str(r#""strict""#).unwrap();
    assert_eq!(strict, CleanProfile::Strict);
}

#[test]
fn test_clean_profile_serde_invalid() {
    let result: Result<CleanProfile, _> = serde_json::from_str(r#""invalid""#);
    assert!(result.is_err());
}
