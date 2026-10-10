use wudo_core::config::{ActionDefinition, Config};
#[test]
fn canonical_definition_tracks_resources_not_format_or_unrelated_actions() {
    let source = include_str!("../../../examples/paperless.actions.toml");
    let a = Config::parse(source.as_bytes())
        .unwrap()
        .definitions()
        .unwrap();
    let b = Config::parse(
        format!(
            "#comment\n{}\n",
            source
                .replace("confirmation = true\ntimeout_seconds", "timeout_seconds")
                .replace(
                    "output_limit_bytes = 16384",
                    "output_limit_bytes = 16_384\nconfirmation = true"
                )
        )
        .as_bytes(),
    )
    .unwrap()
    .definitions()
    .unwrap();
    assert_eq!(a.len(), b.len());
    for (a, b) in a.iter().zip(&b) {
        assert_eq!(a.bytes, b.bytes);
        assert_eq!(ActionDefinition::decode(&a.bytes).unwrap().bytes, a.bytes);
    }
    assert!(ActionDefinition::decode(b"{}").is_err());
    assert!(ActionDefinition::decode(&vec![b' '; 4097]).is_err());
    let edited = source.replace("paperless.service", "changed.service");
    assert_ne!(source, edited);
    let c = Config::parse(edited.as_bytes())
        .unwrap()
        .definitions()
        .unwrap();
    assert!(a.iter().zip(&c).any(|(a, c)| a.bytes != c.bytes));
    let uuid = source
        .lines()
        .find(|l| l.trim_start().starts_with("luks_uuid"))
        .unwrap()
        .split('"')
        .nth(1)
        .unwrap();
    let changed = source.replace(uuid, "11111111-2222-3333-4444-555555555555");
    let c = Config::parse(changed.as_bytes())
        .unwrap()
        .definitions()
        .unwrap();
    for (old, new) in a.iter().zip(c) {
        if old.id == "paperless.stop" {
            assert_eq!(old.bytes, new.bytes);
        } else {
            assert_ne!(old.bytes, new.bytes);
        }
    }
}

#[test]
fn all_capability_fields_and_stored_record_shape_are_binding() {
    let source = include_str!("../../../examples/paperless.actions.toml");
    let original = Config::parse(source.as_bytes())
        .unwrap()
        .definitions()
        .unwrap();
    for (from, to) in [
        ("confirmation = true", "confirmation = false"),
        ("timeout_seconds = 180", "timeout_seconds = 181"),
        ("output_limit_bytes = 16384", "output_limit_bytes = 16385"),
        (
            "mapping_name = \"paperless_crypt\"",
            "mapping_name = \"other_crypt\"",
        ),
        ("id = \"paperless-key\"", "id = \"new-key\""),
    ] {
        let changed = source.replace(from, to);
        assert_ne!(source, changed);
        let definitions = Config::parse(changed.as_bytes())
            .unwrap()
            .definitions()
            .unwrap();
        let old = original.iter().find(|a| a.id == "paperless.start").unwrap();
        let new = definitions
            .iter()
            .find(|a| a.id == "paperless.start")
            .unwrap();
        assert_ne!(old.bytes, new.bytes);
    }
    let value: serde_json::Value = serde_json::from_slice(&original[0].bytes).unwrap();
    assert!(
        ActionDefinition::decode(serde_json::to_string_pretty(&value).unwrap().as_bytes()).is_err()
    );
    let mut unknown = value.clone();
    unknown["format"] = serde_json::json!(2);
    assert!(ActionDefinition::decode(&serde_json::to_vec(&unknown).unwrap()).is_err());
    let duplicate = String::from_utf8(original[0].bytes.clone())
        .unwrap()
        .replace("\"format\":1", "\"format\":1,\"format\":1");
    assert!(ActionDefinition::decode(duplicate.as_bytes()).is_err());
}

#[test]
fn deployed_schema_two_example_has_integration_specific_limits() {
    let config = Config::parse(include_bytes!(
        "../../../examples/paperless.v2.actions.toml"
    ))
    .unwrap();
    assert_eq!(config.schema_version(), 2);
    for (id, action) in config.actions() {
        assert_eq!(
            action.timeout_seconds.is_some(),
            id.as_str() == "storage.unlock"
        );
        assert_eq!(
            action.output_limit_bytes.is_some(),
            id.as_str() == "storage.unlock"
        );
    }
    for definition in config.definitions().unwrap() {
        assert_eq!(
            ActionDefinition::decode(&definition.bytes).unwrap().bytes,
            definition.bytes
        );
    }
}
