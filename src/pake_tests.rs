use super::*;

const DOMAIN: &[u8] = b"example-pake-v1";
const BINDING: &[u8] = b"fixed channel binding";
const SERVER_KEY: [u8; 32] = [0xa5; 32];

#[test]
fn confirmation_kat_pins_the_transcript_key_and_server_identity_binding() {
    let actual = confirmation(&[0x42; 32], BINDING, DOMAIN, SERVER_CONFIRM, &SERVER_KEY);
    assert_eq!(
        hex::encode(actual),
        "c9530e19c3b4f16b3aa804ce0f980377da7427f7cef010d2ddcb0e5627e88335"
    );
}

#[test]
fn both_sides_confirm_the_same_password_binding_and_server_key() {
    let (client, client_message) = Client::begin(b"code", BINDING, DOMAIN);
    let (server, server_message) = Server::begin(b"code", BINDING, DOMAIN);
    let (server_confirmation, expected_client) = server
        .finish(&client_message, &SERVER_KEY)
        .expect("server completes SPAKE2");
    let client_confirmation = client
        .finish(&server_message, &server_confirmation, &SERVER_KEY)
        .expect("client verifies the server");
    expected_client
        .verify(&client_confirmation)
        .expect("server verifies the client");
}

#[test]
fn another_password_or_channel_binding_cannot_confirm() {
    for (password, binding) in [
        (b"wrong".as_slice(), BINDING),
        (b"code".as_slice(), b"another channel".as_slice()),
    ] {
        let (client, client_message) = Client::begin(b"code", BINDING, DOMAIN);
        let (server, server_message) = Server::begin(password, binding, DOMAIN);
        let (server_confirmation, _) = server
            .finish(&client_message, &SERVER_KEY)
            .expect("well-formed SPAKE2 point");
        assert!(matches!(
            client.finish(&server_message, &server_confirmation, &SERVER_KEY),
            Err(PakeError::Confirmation)
        ));
    }
}

#[test]
fn a_substituted_server_key_or_confirmation_is_rejected() {
    let (client, client_message) = Client::begin(b"code", BINDING, DOMAIN);
    let (server, server_message) = Server::begin(b"code", BINDING, DOMAIN);
    let (server_confirmation, _) = server
        .finish(&client_message, &SERVER_KEY)
        .expect("server completes SPAKE2");
    assert!(matches!(
        client.finish(&server_message, &server_confirmation, &[0x5a; 32]),
        Err(PakeError::Confirmation)
    ));
}
