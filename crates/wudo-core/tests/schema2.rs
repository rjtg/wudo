use wudo_core::config::{ActionDefinition, Config};
#[test]
fn systemd_v2_has_no_execution_limits_and_definitions_roundtrip() {
    let v2 = b"schema_version=2\n[resources]\n[actions.demo]\ndescription='Demo'\nconfirmation=true\noperation={kind='systemd-start',unit='demo.service'}\n";
    let config = Config::parse(v2).unwrap();
    assert_eq!(config.schema_version(), 2);
    let definition = config.definitions().unwrap().remove(0);
    assert_eq!(
        ActionDefinition::decode(&definition.bytes).unwrap().bytes,
        definition.bytes
    );
    let mut invalid = v2.to_vec();
    invalid.extend_from_slice(b"timeout_seconds=3\noutput_limit_bytes=0");
    assert!(Config::parse(&invalid).is_err());
    assert!(
        Config::parse(
            &String::from_utf8(v2.to_vec())
                .unwrap()
                .replace("schema_version=2", "schema_version=3")
                .into_bytes()
        )
        .is_err()
    );
}
