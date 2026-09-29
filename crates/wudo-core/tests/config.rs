use wudo_core::config::{Config, ErrorKind, MAX_INPUT_BYTES};

const EXAMPLE: &str = include_str!("../../../examples/paperless.actions.toml");
const EMPTY: &str = "schema_version = 1\n[resources]\n[actions]\n";

#[test]
fn example_and_empty_config_validate_without_provisioning() {
    let config = Config::parse(EXAMPLE.as_bytes()).unwrap();
    assert_eq!(config.actions().len(), 3);
    assert_eq!(config.resources().len(), 1);
    assert!(Config::parse(EMPTY.as_bytes()).is_ok());
}

#[test]
fn rejects_invalid_versions_types_fields_and_references() {
    for (from, to) in [
        ("schema_version = 1", "schema_version = 2"),
        ("schema_version = 1", "schema_version = true"),
        ("schema_version = 1", "schema_version = 1.0"),
        ("schema_version = 1", "schema_version = 1\ncommand = 'bad'"),
        ("kind = \"luks2\"", "kind = \"future\""),
        ("kind = \"luks2\"", "kind = \"luks2\"\npath = '/dev/sda'"),
        (
            "id = \"paperless-key\"",
            "id = \"paperless-key\"\nstate = 'READY'",
        ),
        ("timeout_seconds = 60", "timeout_seconds = 0"),
        ("timeout_seconds = 60", "timeout_seconds = -1"),
        ("timeout_seconds = 60", "timeout_seconds = 601"),
        ("timeout_seconds = 60", "timeout_seconds = true"),
        ("timeout_seconds = 60", "timeout_seconds = 1.5"),
        ("output_limit_bytes = 16384", "output_limit_bytes = 65537"),
        ("output_limit_bytes = 16384", "output_limit_bytes = -1"),
        ("confirmation = true", "confirmation = 'true'"),
        ("confirmation = true", "confirmation = true\nargv = []"),
        (
            "kind = \"luks-unlock\"",
            "kind = \"luks-unlock\"\nunit = 'x.service'",
        ),
        (
            "kind = \"systemd-start\"",
            "kind = \"systemd-start\"\nensure_unlocked = 'x'",
        ),
        ("kind = \"luks-unlocked\"", "kind = \"unknown\""),
        (
            "kind = \"luks-unlocked\"",
            "kind = \"luks-unlocked\"\ncommand = 'bad'",
        ),
        ("resource = \"paperless-storage\"", "resource = \"missing\""),
        ("kind = \"systemd-start\"", "kind = \"systemd-stop\""),
        ("unit = \"paperless.service\"", "unit = '/tmp/bad.service'"),
        ("unit = \"paperless.service\"", "unit = 'bad@x.service'"),
        (
            "mapping_name = \"paperless_crypt\"",
            "mapping_name = '../bad'",
        ),
        ("paperless-key", "bad..key"),
        (
            "11111111-2222-4333-8444-555555555555",
            "00000000-0000-0000-0000-000000000000",
        ),
        (
            "description = \"Unlock Paperless storage\"",
            "description = ' '",
        ),
        ("confirmation = true\n", ""),
    ] {
        let input = EXAMPLE.replace(from, to);
        assert_ne!(input, EXAMPLE, "fixture did not change");
        assert!(
            Config::parse(input.as_bytes()).is_err(),
            "accepted {from} -> {to}"
        );
    }
    for input in [
        "",
        "[actions]\n",
        "schema_version=1\nschema_version=1\n",
        "schema_version=1\n[resources]\n[actions]\n[secrets]\n",
    ] {
        assert!(Config::parse(input.as_bytes()).is_err());
    }
}

#[test]
fn bounds_input_and_rejects_non_utf8_bom_and_deep_input() {
    let mut padded = EMPTY.to_owned();
    padded.push('#');
    padded.extend(std::iter::repeat_n('x', MAX_INPUT_BYTES - padded.len()));
    assert!(Config::parse(padded.as_bytes()).is_ok());
    padded.push('x');
    assert_eq!(
        Config::parse(padded.as_bytes()).unwrap_err().kind(),
        ErrorKind::InputTooLarge
    );
    assert!(Config::parse(&[255]).is_err());
    assert!(Config::parse(format!("\u{feff}{EMPTY}").as_bytes()).is_err());
    let deep = format!("x={}0{}", "[".repeat(1000), "]".repeat(1000));
    assert!(Config::parse(deep.as_bytes()).is_err());
}

#[test]
fn errors_do_not_echo_input_even_in_debug() {
    for input in [
        "TOP_SECRET_CANARY = 'password'",
        "schema_version = 'TOP_SECRET_CANARY'",
        "x='TOP_SECRET_CANARY",
        "[resources.TOP_SECRET_CANARY]\nkind='bad'",
    ] {
        let error = Config::parse(input.as_bytes()).unwrap_err();
        assert!(!format!("{error} {error:?}").contains("TOP_SECRET_CANARY"));
        assert!(error.to_string().len() < 1024);
    }
}

fn root_only(count: usize) -> String {
    let mut text = "schema_version=1\n[resources]\n".to_owned();
    if count == 0 {
        text.push_str("[actions]\n");
    }
    for i in 0..count {
        text.push_str(&format!("[actions.a{i}]\ndescription='Start'\nconfirmation=false\ntimeout_seconds=600\noutput_limit_bytes=0\noperation={{kind='systemd-start',unit='paperless.target'}}\n"));
    }
    text
}
fn resources(count: usize) -> String {
    let mut text = "schema_version=1\n[actions]\n".to_owned();
    for i in 0..count {
        text.push_str(&format!("[resources.r{i}]\nkind='luks2'\nluks_uuid='11111111-2222-3333-4444-{i:012x}'\nmapping_name='map{i}'\nmanaged_secret={{id='key{i}'}}\n"));
    }
    text
}
#[test]
fn counts_root_only_actions_and_unused_resources() {
    assert!(Config::parse(root_only(128).as_bytes()).is_ok());
    assert!(Config::parse(root_only(129).as_bytes()).is_err());
    assert!(Config::parse(resources(32).as_bytes()).is_ok());
    assert!(Config::parse(resources(33).as_bytes()).is_err());
    for (from, to) in [
        ("map1", "map0"),
        ("key1", "key0"),
        ("4444-000000000001", "4444-000000000000"),
    ] {
        assert_eq!(
            Config::parse(resources(2).replace(from, to).as_bytes())
                .unwrap_err()
                .kind(),
            ErrorKind::ConflictingResource
        );
    }
}
#[test]
fn lexical_and_numeric_boundaries() {
    use wudo_core::config::{ActionId, ResourceId, SecretId};
    assert!(ActionId::new("a".repeat(64)).is_ok());
    assert!(ActionId::new("a".repeat(65)).is_err());
    for value in ["", "A", "1a", "a..b", "a_", "a/-b", "a b", "é"] {
        assert!(ResourceId::new(value).is_err());
        assert!(SecretId::new(value).is_err());
    }
    for (from, at_max, beyond) in [
        ("Unlock Paperless storage", "é".repeat(128), "é".repeat(129)),
        ("paperless_crypt", "a".repeat(64), "a".repeat(65)),
        (
            "paperless.service",
            format!("{}.service", "a".repeat(120)),
            format!("{}.service", "a".repeat(121)),
        ),
        ("paperless-storage", "a".repeat(64), "a".repeat(65)),
        ("paperless-key", "a".repeat(64), "a".repeat(65)),
    ] {
        assert!(Config::parse(EXAMPLE.replace(from, &at_max).as_bytes()).is_ok());
        assert!(Config::parse(EXAMPLE.replace(from, &beyond).as_bytes()).is_err());
    }
    assert!(
        Config::parse(
            EXAMPLE
                .replace("timeout_seconds = 60", "timeout_seconds = 1")
                .replace("output_limit_bytes = 16384", "output_limit_bytes = 65536")
                .as_bytes()
        )
        .is_ok()
    );
}

#[test]
fn rejects_deep_dotted_keys_inline_tables_and_prerequisite_lists() {
    let dotted = format!("{}=0", vec!["a"; 1000].join("."));
    let header = format!("[{}]\nx=0", vec!["a"; 1000].join("."));
    let inline = format!("x={}0{}", "{a=".repeat(1000), "}".repeat(1000));
    for input in [dotted, header, inline] {
        assert!(Config::parse(input.as_bytes()).is_err());
    }
    let array = EXAMPLE.replace(
        "[actions.\"paperless.start\".prerequisite]",
        "[[actions.\"paperless.start\".prerequisite]]",
    );
    assert!(Config::parse(array.as_bytes()).is_err());
    for field in [
        "kind = \"luks2\"\n",
        "mapping_name = \"paperless_crypt\"\n",
        "id = \"paperless-key\"\n",
        "resource = \"paperless-storage\"\n",
        "unit = \"paperless.service\"\n",
        "output_limit_bytes = 16384\n",
    ] {
        assert!(Config::parse(EXAMPLE.replace(field, "").as_bytes()).is_err());
    }
}
