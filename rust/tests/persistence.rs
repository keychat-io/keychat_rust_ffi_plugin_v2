//! Persistence tests — verify SQLCipher storage survives restart.
//!
//! These tests use libkeychat directly (not the FFI layer) to avoid
//! global V2 Mutex / tokio runtime contention issues.

use libkeychat::{
    generate_prekey_material, AddressManager, DeviceId, GenericSignedPreKey, IdentityKey,
    IdentityKeyPair, KyberPreKeyId, KyberPreKeyRecord, PreKeyId, PreKeyRecord, ProtocolAddress,
    SecureStorage, SignalParticipant, SignalPreKeyMaterial, SignalPrivateKey, SignedPreKeyId,
    SignedPreKeyRecord,
};
use std::sync::{Arc, Mutex};

const DB_KEY: &str = "test-passphrase-2024";

fn temp_db_path(name: &str) -> String {
    let dir = std::env::temp_dir();
    let path = dir.join(format!("keychat_test_{name}_{}.db", std::process::id()));
    path.to_str().unwrap().to_string()
}

fn cleanup(path: &str) {
    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_file(format!("{path}-wal"));
    let _ = std::fs::remove_file(format!("{path}-shm"));
}

/// Helper: save SignalPreKeyMaterial to the DB.
fn save_keys(db: &SecureStorage, peer_id: &str, dev_id: u32, keys: &SignalPreKeyMaterial) {
    db.save_signal_participant(
        peer_id,
        dev_id,
        &keys.identity_key_pair.identity_key().serialize(),
        &keys.identity_key_pair.private_key().serialize(),
        keys.registration_id,
        u32::from(keys.signed_prekey_id),
        &keys.signed_prekey.serialize().unwrap(),
        u32::from(keys.prekey_id),
        &keys.prekey.serialize().unwrap(),
        u32::from(keys.kyber_prekey_id),
        &keys.kyber_prekey.serialize().unwrap(),
    )
    .unwrap();
}

/// Helper: load and reconstruct SignalPreKeyMaterial from DB.
fn load_keys(db: &SecureStorage, peer_id: &str) -> (u32, SignalPreKeyMaterial) {
    let (dev_id, id_pub, id_priv, reg_id, spk_id, spk_rec, pk_id, pk_rec, kpk_id, kpk_rec) =
        db.load_signal_participant(peer_id).unwrap().unwrap();

    let identity_key = IdentityKey::decode(&id_pub).unwrap();
    let private_key = SignalPrivateKey::deserialize(&id_priv).unwrap();
    let keys = SignalPreKeyMaterial {
        identity_key_pair: IdentityKeyPair::new(identity_key, private_key),
        registration_id: reg_id,
        signed_prekey_id: SignedPreKeyId::from(spk_id),
        signed_prekey: SignedPreKeyRecord::deserialize(&spk_rec).unwrap(),
        prekey_id: PreKeyId::from(pk_id),
        prekey: PreKeyRecord::deserialize(&pk_rec).unwrap(),
        kyber_prekey_id: KyberPreKeyId::from(kpk_id),
        kyber_prekey: KyberPreKeyRecord::deserialize(&kpk_rec).unwrap(),
    };
    (dev_id, keys)
}

// ─── Test 1: Full Signal session — encrypt, restart, verify identity ────────

#[test]
fn test_signal_session_identity_survives_restart() {
    let db_path = temp_db_path("signal_identity");
    cleanup(&db_path);

    let alice_name = "alice";
    let bob_signal_id: String;
    let alice_signal_id: String;

    // Phase 1: create persistent participant, establish session, encrypt
    {
        let storage = Arc::new(Mutex::new(SecureStorage::open(&db_path, DB_KEY).unwrap()));
        let alice_keys = generate_prekey_material().unwrap();
        let mut bob = SignalParticipant::new("bob", 1).unwrap();

        let mut alice = SignalParticipant::persistent(
            alice_name.into(),
            1,
            alice_keys.clone(),
            storage.clone(),
        )
        .unwrap();

        alice_signal_id = alice.identity_public_key_hex();
        bob_signal_id = bob.identity_public_key_hex();

        // Establish session: Alice processes Bob's bundle
        let bob_bundle = bob.prekey_bundle().unwrap();
        let bob_addr = ProtocolAddress::new(bob_signal_id.clone(), DeviceId::new(1).unwrap());
        let alice_addr = ProtocolAddress::new(alice_signal_id.clone(), DeviceId::new(1).unwrap());

        alice.process_prekey_bundle(&bob_addr, &bob_bundle).unwrap();

        // Alice encrypts → Bob decrypts
        let ct = alice.encrypt(&bob_addr, b"hello from alice").unwrap();
        let pt = bob.decrypt(&alice_addr, &ct.bytes).unwrap();
        assert_eq!(String::from_utf8(pt.plaintext).unwrap(), "hello from alice");

        // Save Alice's keys to DB
        save_keys(&storage.lock().unwrap(), &bob_signal_id, 1, &alice_keys);

        eprintln!("✅ Phase 1: session established, encrypt/decrypt works");
    }

    // Phase 2: "restart" — reconstruct Alice from DB, verify identity
    {
        let storage = Arc::new(Mutex::new(SecureStorage::open(&db_path, DB_KEY).unwrap()));

        let (dev_id, restored_keys) = load_keys(&storage.lock().unwrap(), &bob_signal_id);
        assert_eq!(dev_id, 1);

        let alice_restored = SignalParticipant::persistent(
            alice_name.into(),
            dev_id,
            restored_keys,
            storage.clone(),
        )
        .unwrap();

        // Identity key must survive restart
        assert_eq!(
            alice_restored.identity_public_key_hex(),
            alice_signal_id,
            "Alice's identity key must match after restart"
        );

        eprintln!("✅ Phase 2: identity key restored from DB");
    }

    cleanup(&db_path);
}

// ─── Test 2: Key material DB roundtrip ──────────────────────────────────────

#[test]
fn test_key_material_roundtrip() {
    let db_path = temp_db_path("key_roundtrip");
    cleanup(&db_path);

    let original_keys = generate_prekey_material().unwrap();

    // Save
    {
        let db = SecureStorage::open(&db_path, DB_KEY).unwrap();
        save_keys(&db, "peer-abc", 2, &original_keys);

        let list = db.list_signal_participants().unwrap();
        assert_eq!(list, vec!["peer-abc"]);
    }

    // Reopen and verify all fields match
    {
        let db = SecureStorage::open(&db_path, DB_KEY).unwrap();

        let list = db.list_signal_participants().unwrap();
        assert_eq!(list, vec!["peer-abc"], "participant must survive reopen");

        let (dev_id, loaded_keys) = load_keys(&db, "peer-abc");
        assert_eq!(dev_id, 2);
        assert_eq!(loaded_keys.registration_id, original_keys.registration_id);
        assert_eq!(
            u32::from(loaded_keys.signed_prekey_id),
            u32::from(original_keys.signed_prekey_id)
        );
        assert_eq!(
            u32::from(loaded_keys.prekey_id),
            u32::from(original_keys.prekey_id)
        );
        assert_eq!(
            u32::from(loaded_keys.kyber_prekey_id),
            u32::from(original_keys.kyber_prekey_id)
        );
        assert_eq!(
            loaded_keys.identity_key_pair.identity_key().serialize(),
            original_keys.identity_key_pair.identity_key().serialize(),
            "identity public key must match"
        );
        assert_eq!(
            loaded_keys.identity_key_pair.private_key().serialize(),
            original_keys.identity_key_pair.private_key().serialize(),
            "identity private key must match"
        );

        // Delete and verify
        db.delete_signal_participant("peer-abc").unwrap();
        assert!(db.list_signal_participants().unwrap().is_empty());
    }

    cleanup(&db_path);
    eprintln!("✅ Key material roundtrip passed — all fields match");
}

// ─── Test 3: Pending friend request roundtrip ───────────────────────────────

#[test]
fn test_pending_fr_roundtrip() {
    let db_path = temp_db_path("pending_fr");
    cleanup(&db_path);

    let keys = generate_prekey_material().unwrap();

    {
        let db = SecureStorage::open(&db_path, DB_KEY).unwrap();
        db.save_pending_fr(
            "fr-001",
            1,
            &keys.identity_key_pair.identity_key().serialize(),
            &keys.identity_key_pair.private_key().serialize(),
            keys.registration_id,
            u32::from(keys.signed_prekey_id),
            &keys.signed_prekey.serialize().unwrap(),
            u32::from(keys.prekey_id),
            &keys.prekey.serialize().unwrap(),
            u32::from(keys.kyber_prekey_id),
            &keys.kyber_prekey.serialize().unwrap(),
            "secret-inbox-hex",
        )
        .unwrap();
    }

    // Reopen
    {
        let db = SecureStorage::open(&db_path, DB_KEY).unwrap();
        let list = db.list_pending_frs().unwrap();
        assert_eq!(list, vec!["fr-001"], "pending FR must survive reopen");

        let (dev, _pub, _priv, reg, _s, _sr, _p, _pr, _k, _kr, secret) =
            db.load_pending_fr("fr-001").unwrap().unwrap();
        assert_eq!(dev, 1);
        assert_eq!(reg, keys.registration_id);
        assert_eq!(secret, "secret-inbox-hex");

        db.delete_pending_fr("fr-001").unwrap();
        assert!(db.list_pending_frs().unwrap().is_empty());
    }

    cleanup(&db_path);
    eprintln!("✅ Pending FR roundtrip passed");
}

// ─── Test 4: Event dedup survives restart ───────────────────────────────────

#[test]
fn test_event_dedup_persists() {
    let db_path = temp_db_path("event_dedup");
    cleanup(&db_path);

    // Write
    {
        let db = SecureStorage::open(&db_path, DB_KEY).unwrap();
        db.mark_event_processed("evt-aaa").unwrap();
        db.mark_event_processed("evt-bbb").unwrap();
        assert!(db.is_event_processed("evt-aaa").unwrap());
        assert!(!db.is_event_processed("evt-ccc").unwrap());
    }

    // Reopen
    {
        let db = SecureStorage::open(&db_path, DB_KEY).unwrap();
        assert!(
            db.is_event_processed("evt-aaa").unwrap(),
            "evt-aaa must survive"
        );
        assert!(
            db.is_event_processed("evt-bbb").unwrap(),
            "evt-bbb must survive"
        );
        assert!(
            !db.is_event_processed("evt-ccc").unwrap(),
            "evt-ccc was never marked"
        );
    }

    cleanup(&db_path);
    eprintln!("✅ Event dedup persists across restart");
}

// ─── Test 5: Address manager persistence ────────────────────────────────────

#[test]
fn test_address_manager_persists() {
    let db_path = temp_db_path("addr_mgr");
    cleanup(&db_path);

    {
        let db = SecureStorage::open(&db_path, DB_KEY).unwrap();
        let mut mgr = AddressManager::new();
        mgr.add_peer("peer-x", Some("inbox-x".into()), Some("npub-x".into()));
        if let Some(ser) = mgr.to_serialized("peer-x") {
            db.save_peer_addresses("peer-x", &ser).unwrap();
        }
    }

    {
        let db = SecureStorage::open(&db_path, DB_KEY).unwrap();
        let all = db.load_all_peer_addresses().unwrap();
        assert_eq!(all.len(), 1);
        let (id, state) = &all[0];
        assert_eq!(id, "peer-x");
        assert_eq!(state.peer_first_inbox.as_deref(), Some("inbox-x"));
        assert_eq!(state.peer_nostr_pubkey.as_deref(), Some("npub-x"));

        let mgr = AddressManager::from_serialized(id, state.clone());
        assert_eq!(mgr.resolve_send_address("peer-x").unwrap(), "inbox-x");
    }

    cleanup(&db_path);
    eprintln!("✅ AddressManager persists across restart");
}

// ─── Test 6: Wrong DB key rejected (SQLCipher encryption) ───────────────────

#[test]
fn test_wrong_db_key_rejected() {
    let db_path = temp_db_path("wrong_key");
    cleanup(&db_path);

    {
        let db = SecureStorage::open(&db_path, DB_KEY).unwrap();
        db.mark_event_processed("evt-1").unwrap();
    }

    let result = SecureStorage::open(&db_path, "wrong-passphrase");
    assert!(result.is_err(), "Wrong key must be rejected");

    cleanup(&db_path);
    eprintln!("✅ SQLCipher encryption verified — wrong key rejected");
}

// ─── Test 7: Two-party Signal session with persistence ──────────────────────

#[test]
fn test_two_party_signal_full_lifecycle() {
    let alice_db = temp_db_path("alice_signal");
    let bob_db = temp_db_path("bob_signal");
    cleanup(&alice_db);
    cleanup(&bob_db);

    let alice_id: String;
    let bob_id: String;

    // Phase 1: Alice and Bob establish session, exchange messages
    {
        let alice_storage = Arc::new(Mutex::new(SecureStorage::open(&alice_db, DB_KEY).unwrap()));
        let bob_storage = Arc::new(Mutex::new(SecureStorage::open(&bob_db, DB_KEY).unwrap()));

        let alice_keys = generate_prekey_material().unwrap();
        let bob_keys = generate_prekey_material().unwrap();

        let mut alice = SignalParticipant::persistent(
            "alice".into(),
            1,
            alice_keys.clone(),
            alice_storage.clone(),
        )
        .unwrap();
        let mut bob =
            SignalParticipant::persistent("bob".into(), 1, bob_keys.clone(), bob_storage.clone())
                .unwrap();

        alice_id = alice.identity_public_key_hex();
        bob_id = bob.identity_public_key_hex();

        let bob_addr = ProtocolAddress::new(bob_id.clone(), DeviceId::new(1).unwrap());
        let alice_addr = ProtocolAddress::new(alice_id.clone(), DeviceId::new(1).unwrap());

        // Alice → Bob: process bundle + encrypt
        let bob_bundle = bob.prekey_bundle().unwrap();
        alice.process_prekey_bundle(&bob_addr, &bob_bundle).unwrap();

        let ct1 = alice.encrypt(&bob_addr, b"msg1: hello bob").unwrap();
        let pt1 = bob.decrypt(&alice_addr, &ct1.bytes).unwrap();
        assert_eq!(String::from_utf8(pt1.plaintext).unwrap(), "msg1: hello bob");

        // Bob → Alice: reply (direction change, ratchet advances)
        let ct2 = bob.encrypt(&alice_addr, b"msg2: hi alice").unwrap();
        let pt2 = alice.decrypt(&bob_addr, &ct2.bytes).unwrap();
        assert_eq!(String::from_utf8(pt2.plaintext).unwrap(), "msg2: hi alice");

        // Alice → Bob: another message
        let ct3 = alice.encrypt(&bob_addr, b"msg3: how are you").unwrap();
        let pt3 = bob.decrypt(&alice_addr, &ct3.bytes).unwrap();
        assert_eq!(
            String::from_utf8(pt3.plaintext).unwrap(),
            "msg3: how are you"
        );

        // Save both to DB
        save_keys(&alice_storage.lock().unwrap(), &bob_id, 1, &alice_keys);
        save_keys(&bob_storage.lock().unwrap(), &alice_id, 1, &bob_keys);

        eprintln!("✅ Phase 1: 3 messages exchanged successfully");
    }

    // Phase 2: Both restart, continue conversation
    {
        let alice_storage = Arc::new(Mutex::new(SecureStorage::open(&alice_db, DB_KEY).unwrap()));
        let bob_storage = Arc::new(Mutex::new(SecureStorage::open(&bob_db, DB_KEY).unwrap()));

        let (_, alice_keys) = load_keys(&alice_storage.lock().unwrap(), &bob_id);
        let (_, bob_keys) = load_keys(&bob_storage.lock().unwrap(), &alice_id);

        let mut alice =
            SignalParticipant::persistent("alice".into(), 1, alice_keys, alice_storage.clone())
                .unwrap();
        let mut bob =
            SignalParticipant::persistent("bob".into(), 1, bob_keys, bob_storage.clone()).unwrap();

        // Identity keys must survive
        assert_eq!(alice.identity_public_key_hex(), alice_id);
        assert_eq!(bob.identity_public_key_hex(), bob_id);

        let bob_addr = ProtocolAddress::new(bob_id.clone(), DeviceId::new(1).unwrap());
        let alice_addr = ProtocolAddress::new(alice_id.clone(), DeviceId::new(1).unwrap());

        // Continue conversation: Bob → Alice (tests that session state survived)
        let ct4 = bob
            .encrypt(&alice_addr, b"msg4: survived restart!")
            .unwrap();
        let pt4 = alice.decrypt(&bob_addr, &ct4.bytes).unwrap();
        assert_eq!(
            String::from_utf8(pt4.plaintext).unwrap(),
            "msg4: survived restart!",
            "decryption must work after restart"
        );

        // Alice → Bob
        let ct5 = alice
            .encrypt(&bob_addr, b"msg5: persistence works!")
            .unwrap();
        let pt5 = bob.decrypt(&alice_addr, &ct5.bytes).unwrap();
        assert_eq!(
            String::from_utf8(pt5.plaintext).unwrap(),
            "msg5: persistence works!",
        );

        eprintln!("✅ Phase 2: conversation continues after restart — persistence works!");
    }

    cleanup(&alice_db);
    cleanup(&bob_db);
}

// ─── Test 8: Peer mapping persistence ───────────────────────────────────────

#[test]
fn test_peer_mapping_persists() {
    let db_path = temp_db_path("peer_map");
    cleanup(&db_path);

    {
        let db = SecureStorage::open(&db_path, DB_KEY).unwrap();
        db.save_peer_mapping("npub1alice", "signal-alice", "Alice")
            .unwrap();
        db.save_peer_mapping("npub1bob", "signal-bob", "Bob")
            .unwrap();
    }

    {
        let db = SecureStorage::open(&db_path, DB_KEY).unwrap();
        let peers = db.list_peers().unwrap();
        assert_eq!(peers.len(), 2, "2 peers must survive restart");

        let alice = db.load_peer_by_nostr("npub1alice").unwrap().unwrap();
        assert_eq!(alice.signal_id, "signal-alice");
        assert_eq!(alice.name, "Alice");

        let bob = db.load_peer_by_signal("signal-bob").unwrap().unwrap();
        assert_eq!(bob.nostr_pubkey, "npub1bob");
        assert_eq!(bob.name, "Bob");
    }

    cleanup(&db_path);
    eprintln!("✅ Peer mapping persists across restart");
}
