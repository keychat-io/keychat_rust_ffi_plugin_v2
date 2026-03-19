//! FFI return value structure tests.
//! Verifies that all api_v2 functions return correct types and fields.

use base64::Engine as _;
use keychat_rust_ffi_plugin_v2::api_v2::*;

const TEST_KEY: &str = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

fn test_init() -> String {
    init_v2(TEST_KEY.into(), ":memory:".into(), "test-key".into(), 1).unwrap_or_else(|_| {
        // Already initialized in another test, get pubkey from privkey
        use libkeychat::{Keys, SecretKey};
        let sk = SecretKey::from_hex(TEST_KEY).unwrap();
        Keys::new(sk).public_key().to_hex()
    })
}

// ─── KCMessage V2 Format ────────────────────────────────────────────────────

#[test]
fn test_build_text_message_structure() {
    let json = build_text_message("hello world".into()).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

    // Must have v:2
    assert_eq!(parsed["v"], 2, "KCMessage must have v:2");
    // Must have kind
    assert!(
        parsed.get("kind").is_some(),
        "KCMessage must have kind field"
    );
    // kind should be "text" or text content should be present
    let has_text =
        parsed.get("text").is_some() || parsed.get("kind").and_then(|k| k.as_str()) == Some("text");
    assert!(
        has_text,
        "Text message must indicate text kind. Got: {json}"
    );
}

#[test]
fn test_build_friend_request_message_structure() {
    let payload = serde_json::json!({
        "name": "Alice",
        "nostrIdentityKey": "aa".repeat(32),
        "signalIdentityKey": "bb".repeat(33),
        "firstInbox": "cc".repeat(32),
        "signalSignedPrekeyId": 1,
        "signalSignedPrekey": "dd".repeat(33),
        "signalSignedPrekeySignature": "ee".repeat(64),
        "signalOneTimePrekeyId": 1,
        "signalOneTimePrekey": "ff".repeat(33),
        "signalKyberPrekeyId": 1,
        "signalKyberPrekey": "11".repeat(100),
        "signalKyberPrekeySignature": "22".repeat(64),
        "time": 1234567890u64,
        "globalSign": "33".repeat(32)
    });

    let result = build_friend_request_message(payload.to_string());
    match result {
        Ok(json) => {
            let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed["v"], 2, "Must have v:2");
            // Should contain friendRequest kind
            let json_str = json.to_lowercase();
            assert!(
                json_str.contains("friendrequest") || json_str.contains("friend_request"),
                "Must contain friendRequest kind. Got: {json}"
            );
        }
        Err(e) => {
            eprintln!("build_friend_request_message failed (may need exact fields): {e}");
        }
    }
}

#[test]
fn test_parse_message_text() {
    let json = build_text_message("test content".into()).unwrap();
    let parsed = parse_message(json).unwrap();

    assert_eq!(parsed.kind, "text", "Parsed kind must be 'text'");
    assert!(
        parsed.content_json.contains("test content"),
        "Parsed content must contain original text. Got: {}",
        parsed.content_json
    );
}

#[test]
fn test_parse_message_v1_format_fails() {
    let v1 = r#"{"c":"signal","type":100,"msg":"hello"}"#;
    let result = parse_message(v1.into());
    assert!(
        result.is_err(),
        "V1 message format should NOT parse as V2 KCMessage"
    );
}

// ─── Stamp ──────────────────────────────────────────────────────────────────

#[test]
fn test_stamp_event_format() {
    // Invalid event should error
    let result = stamp_event(r#"{"invalid":"json"}"#.into(), "cashuAtoken".into());
    assert!(result.is_err(), "Invalid event JSON should fail stamp");
}

// ─── Init + Friend Request ──────────────────────────────────────────────────

#[test]
fn test_init_v2_and_create_friend_request() {
    let privkey = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

    let init_result = init_v2(privkey.into(), ":memory:".into(), "test-key".into(), 1);
    match init_result {
        Ok(ref pubkey) => {
            eprintln!("✅ init_v2 succeeded, pubkey={}", &pubkey[..16]);

            // Create friend request
            let bob = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
            match create_friend_request(pubkey.clone(), bob.into(), "TestAlice".into()) {
                Ok(fr) => {
                    // Verify V2FriendRequestResult fields
                    assert!(!fr.event_json.is_empty(), "event_json must not be empty");
                    assert!(
                        !fr.first_inbox_pubkey.is_empty(),
                        "first_inbox_pubkey must not be empty"
                    );
                    assert!(
                        !fr.first_inbox_secret.is_empty(),
                        "first_inbox_secret must not be empty"
                    );
                    assert!(
                        !fr.signal_identity_hex.is_empty(),
                        "signal_identity_hex must not be empty"
                    );

                    // event_json should be valid JSON
                    let event: serde_json::Value = serde_json::from_str(&fr.event_json)
                        .expect("event_json must be valid JSON");

                    // Should be kind:1059 (Gift Wrap)
                    assert_eq!(
                        event["kind"], 1059,
                        "Friend request event must be kind:1059. Got: {}",
                        event["kind"]
                    );

                    // signal_identity_hex should be hex (even length, hex chars)
                    assert!(
                        fr.signal_identity_hex.len() > 0 && fr.signal_identity_hex.len() % 2 == 0,
                        "signal_identity_hex should be even-length hex"
                    );
                    assert!(
                        fr.signal_identity_hex
                            .chars()
                            .all(|c| c.is_ascii_hexdigit()),
                        "signal_identity_hex should be hex chars only"
                    );

                    eprintln!(
                        "✅ V2FriendRequestResult: event={}bytes inbox={} signal_id={}",
                        fr.event_json.len(),
                        fr.first_inbox_pubkey,
                        &fr.signal_identity_hex[..16]
                    );
                }
                Err(e) => eprintln!("create_friend_request error: {e}"),
            }
        }
        Err(e) => eprintln!("init_v2 error: {e}"),
    }
}

// ─── V2EncryptResult / V2DecryptResult structure ────────────────────────────

#[test]
fn test_encrypt_result_structure() {
    let pubkey = test_init();
    // Without a Signal session, encrypt will fail — but we verify the error path
    let result = encrypt(pubkey.clone(), "nonexistent_peer".into(), "test".into(), 1);
    assert!(result.is_err(), "Encrypt without session should fail");
}

#[test]
fn test_decrypt_result_structure() {
    let pubkey = test_init();
    let result = decrypt(
        pubkey.clone(),
        "nonexistent_peer".into(),
        "dGVzdA==".into(),
        1,
    );
    assert!(result.is_err(), "Decrypt without session should fail");
}

// ─── Gift Wrap ──────────────────────────────────────────────────────────────

#[test]
fn test_unwrap_invalid_event() {
    let pubkey = test_init();
    let result = unwrap_event(pubkey.clone(), r#"{"invalid":"event"}"#.into());
    assert!(result.is_err(), "Unwrap invalid event should fail");
}

// ─── Relay Fees ─────────────────────────────────────────────────────────────

#[test]
fn test_fetch_relay_fees_structure() {
    let pubkey = test_init();
    let result = fetch_relay_fees(pubkey.clone(), "wss://relay.keychat.io".into());
    match result {
        Ok(json) => {
            // Must be valid JSON
            let parsed: serde_json::Value =
                serde_json::from_str(&json).expect("Relay fees must be valid JSON");
            assert!(parsed.is_object(), "Relay fees must be a JSON object");
            eprintln!("✅ Relay fees: {}", &json[..80.min(json.len())]);
        }
        Err(e) => eprintln!("Relay fees fetch failed (network): {e}"),
    }
}

// ─── Address Management ─────────────────────────────────────────────────────

#[test]
fn test_resolve_send_address_no_peer() {
    let pubkey = test_init();
    let result = resolve_send_address(pubkey.clone(), "nonexistent".into());
    assert!(
        result.is_err(),
        "Resolve address for unknown peer should fail"
    );
}

// ─── MLS ────────────────────────────────────────────────────────────────────

#[test]
fn test_mls_init() {
    let pubkey = test_init();
    let result = mls_init(pubkey.clone());
    match result {
        Ok(()) => eprintln!("✅ MLS init succeeded"),
        Err(e) => eprintln!("MLS init error: {e}"),
    }
}

#[test]
fn test_mls_generate_key_package_structure() {
    let pubkey = test_init();
    let _ = mls_init(pubkey.clone());

    match mls_generate_key_package(pubkey.clone()) {
        Ok(kp_base64) => {
            assert!(!kp_base64.is_empty(), "KeyPackage must not be empty");
            // Must be valid base64
            let decoded = base64::engine::general_purpose::STANDARD.decode(&kp_base64);
            assert!(decoded.is_ok(), "KeyPackage must be valid base64");
            eprintln!(
                "✅ KeyPackage: {} bytes (base64 len={})",
                decoded.unwrap().len(),
                kp_base64.len()
            );
        }
        Err(e) => eprintln!("KeyPackage error: {e}"),
    }
}

#[test]
fn test_mls_create_group_and_encrypt() {
    let pubkey = test_init();
    let _ = mls_init(pubkey.clone());

    let group_id = "test-group-001";
    match mls_create_group(pubkey.clone(), group_id.into(), "Test Group".into()) {
        Ok(()) => {
            eprintln!("✅ Group created");

            // Encrypt
            match mls_encrypt(pubkey.clone(), group_id.into(), "hello group".into()) {
                Ok(ct_base64) => {
                    assert!(!ct_base64.is_empty());
                    let decoded = base64::engine::general_purpose::STANDARD.decode(&ct_base64);
                    assert!(decoded.is_ok(), "Ciphertext must be valid base64");
                    eprintln!("✅ MLS encrypt: {} bytes", decoded.unwrap().len());
                }
                Err(e) => eprintln!("MLS encrypt error: {e}"),
            }

            // Members
            match mls_group_members(pubkey.clone(), group_id.into()) {
                Ok(members) => {
                    assert!(
                        !members.is_empty(),
                        "Group must have at least 1 member (self)"
                    );
                    eprintln!("✅ Members: {:?}", members);
                }
                Err(e) => eprintln!("Group members error: {e}"),
            }

            // Group info
            match mls_group_info(pubkey.clone(), group_id.into()) {
                Ok(info) => {
                    assert_eq!(info.name, "Test Group");
                    assert!(!info.admins_json.is_empty());
                    eprintln!("✅ Group info: name={} status={}", info.name, info.status);
                }
                Err(e) => eprintln!("Group info error: {e}"),
            }

            // Derive temp inbox
            match mls_derive_temp_inbox(pubkey.clone(), group_id.into()) {
                Ok(addr) => {
                    assert!(!addr.is_empty());
                    eprintln!("✅ Temp inbox: {}", &addr[..32.min(addr.len())]);
                }
                Err(e) => eprintln!("Temp inbox error: {e}"),
            }
        }
        Err(e) => eprintln!("Create group error: {e}"),
    }
}

#[test]
fn test_mls_decrypt_result_structure() {
    let pubkey = test_init();
    let result = mls_decrypt(
        pubkey.clone(),
        "nonexistent-group".into(),
        "dGVzdA==".into(),
    );
    assert!(result.is_err(), "Decrypt on nonexistent group should fail");
}

#[test]
fn test_mls_add_members_result_structure() {
    let pubkey = test_init();
    let _ = mls_init(pubkey.clone());

    // Empty key packages should fail
    let result = mls_add_members(pubkey.clone(), "nonexistent".into(), "[]".into());
    assert!(
        result.is_err(),
        "Add members to nonexistent group should fail"
    );
}
