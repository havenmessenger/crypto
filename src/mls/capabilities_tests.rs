//! The bytes a leaf's capabilities encode to: fixed here, so a change of what the library fills in can't move them.

use super::*;
use tls_codec::Serialize as _;

/// Version 1.0, suites 0x0001 to 0x0003, no extensions, no proposals, Basic credentials.
const PLAIN: &str = "0200010600010002000300000200 01";
/// Version 1.0, suite 0x0001, no extensions, the participant-list proposal 0xF7A0, Basic credentials.
const APPSYNC: &str = "020001020001000 2f7a0020001";

fn hex_of(capabilities: &Capabilities) -> String {
    hex::encode(capabilities.tls_serialize_detached().unwrap())
}

fn expected(text: &str) -> String {
    text.replace(' ', "")
}

#[test]
fn a_plain_leaf_advertises_what_it_always_has() {
    assert_eq!(hex_of(&plain_leaf_capabilities()), expected(PLAIN));
}

#[test]
fn a_leaf_that_can_carry_the_roster_advertises_what_it_always_has() {
    assert_eq!(
        hex_of(&crate::mimi::mimi_appsync_capabilities()),
        expected(APPSYNC)
    );
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

#[test]
fn a_key_package_is_built_with_those_lists() {
    let (_, plain, _) = crate::identity::generate_identity("plain@as.test".into(), now()).unwrap();
    let (_, appsync, _) =
        crate::mimi::mimi_generate_identity("appsync@as.test".into(), now()).unwrap();
    for (package, wanted) in [(plain, PLAIN), (appsync, APPSYNC)] {
        let package = hex::encode(package);
        assert!(
            package.contains(&expected(wanted)),
            "{wanted} not in {package}"
        );
    }
}
