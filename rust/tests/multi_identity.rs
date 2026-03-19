//! Multi-identity tests: verify multiple identities coexist and persist independently.
//! Includes Signal session persistence across restart for multiple identities.

use std::sync::{Arc, Mutex};

use keychat_rust_ffi_plugin_v2::api_v2::*;
use libkeychat::{
    generate_prekey_material, DeviceId, GenericSignedPreKey, IdentityKey, IdentityKeyPair,
    KyberPreKeyId, KyberPreKeyRecord, PreKeyId, PreKeyRecord, ProtocolAddress, SecureStorage,
    SignalParticipant, SignalPreKeyMaterial, SignalPrivateKey, SignedPreKeyId, SignedPreKeyRecord,
};

const ALICE_PRIVKEY: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const BOB_PRIVKEY: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const CHARLIE_PRIVKEY: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const DB_KEY: &str = "test-passphrase-multi";

fn temp_db(name: &str) -> String {
    let dir = std::env::temp_dir();
    dir.join(format!("keychat_multi_{name}_{}.db", std::process::id()))
        .to_str()
        .unwrap()
        .to_string()
}

fn cleanup(path: &str) {
    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_file(format!("{path}-wal"));
    let _ = std::fs::remove_file(format!("{path}-shm"));
}

// ─── Test 1: Multiple identities coexist, state isolated ────────────────────

#[test]
fn test_multi_identity_coexist_and_isolated() {
    let db_a = temp_db("alice");
    let db_b = temp_db("bob");
    let db_c = temp_db("charlie");
    cleanup(&db_a);
    cleanup(&db_b);
    cleanup(&db_c);

    // Phase 1: init 3 identities, each with its own DB
    let alice_pk = init_v2(ALICE_PRIVKEY.into(), db_a.clone(), DB_KEY.into(), 1).unwrap();
    let bob_pk = init_v2(BOB_PRIVKEY.into(), db_b.clone(), DB_KEY.into(), 2).unwrap();
    let charlie_pk = init_v2(CHARLIE_PRIVKEY.into(), db_c.clone(), DB_KEY.into(), 3).unwrap();

    assert_ne!(alice_pk, bob_pk);
    assert_ne!(bob_pk, charlie_pk);
    eprintln!("✅ 3 identities initialized");

    // Each has its own device_id
    assert_eq!(get_device_id(alice_pk.clone()).unwrap(), 1);
    assert_eq!(get_device_id(bob_pk.clone()).unwrap(), 2);
    assert_eq!(get_device_id(charlie_pk.clone()).unwrap(), 3);
    eprintln!("✅ device_id isolated (1, 2, 3)");

    // Event dedup isolated
    mark_event_processed(alice_pk.clone(), "evt-shared".into()).unwrap();
    assert!(is_event_processed(alice_pk.clone(), "evt-shared".into()).unwrap());
    assert!(
        !is_event_processed(bob_pk.clone(), "evt-shared".into()).unwrap(),
        "Bob should NOT see Alice's event"
    );
    assert!(
        !is_event_processed(charlie_pk.clone(), "evt-shared".into()).unwrap(),
        "Charlie should NOT see Alice's event"
    );
    eprintln!("✅ Event dedup isolated across identities");

    // Peer registration isolated
    register_peer(
        alice_pk.clone(),
        "signal-peer-1".into(),
        "npub-peer-1".into(),
        Some("inbox-1".into()),
    )
    .unwrap();
    assert_eq!(
        resolve_send_address(alice_pk.clone(), "signal-peer-1".into()).unwrap(),
        "inbox-1"
    );
    assert!(
        resolve_send_address(bob_pk.clone(), "signal-peer-1".into()).is_err(),
        "Bob should NOT see Alice's peer"
    );
    eprintln!("✅ Peer state isolated across identities");

    // MLS isolated
    mls_init(alice_pk.clone()).unwrap();
    mls_init(bob_pk.clone()).unwrap();
    mls_create_group(alice_pk.clone(), "grp-a".into(), "Alice Group".into()).unwrap();
    mls_create_group(bob_pk.clone(), "grp-b".into(), "Bob Group".into()).unwrap();

    assert!(mls_group_members(alice_pk.clone(), "grp-a".into()).is_ok());
    assert!(
        mls_group_members(alice_pk.clone(), "grp-b".into()).is_err(),
        "Alice should NOT see Bob's group"
    );
    assert!(mls_group_members(bob_pk.clone(), "grp-b".into()).is_ok());
    assert!(
        mls_group_members(bob_pk.clone(), "grp-a".into()).is_err(),
        "Bob should NOT see Alice's group"
    );
    eprintln!("✅ MLS groups isolated across identities");

    // list_identities returns all three
    let ids = list_identities().unwrap();
    assert_eq!(ids.len(), 3);
    assert!(ids.contains(&alice_pk));
    assert!(ids.contains(&bob_pk));
    assert!(ids.contains(&charlie_pk));
    eprintln!("✅ list_identities returns all 3");

    // Destroy Bob, others survive
    destroy_identity(bob_pk.clone()).unwrap();
    assert!(get_device_id(bob_pk.clone()).is_err(), "Bob gone");
    assert_eq!(get_device_id(alice_pk.clone()).unwrap(), 1, "Alice intact");
    assert_eq!(
        get_device_id(charlie_pk.clone()).unwrap(),
        3,
        "Charlie intact"
    );
    assert_eq!(list_identities().unwrap().len(), 2);
    eprintln!("✅ destroy_identity only removes target");

    destroy_identity(alice_pk).unwrap();
    destroy_identity(charlie_pk).unwrap();
    cleanup(&db_a);
    cleanup(&db_b);
    cleanup(&db_c);
}

// ─── Test 2: Multi-identity state persists across restart ───────────────────

#[test]
fn test_multi_identity_persistence() {
    let db_a = temp_db("persist_alice");
    let db_b = temp_db("persist_bob");
    cleanup(&db_a);
    cleanup(&db_b);

    let alice_pk: String;
    let bob_pk: String;

    // Phase 1: init two identities, write state
    {
        alice_pk = init_v2(ALICE_PRIVKEY.into(), db_a.clone(), DB_KEY.into(), 1).unwrap();
        bob_pk = init_v2(BOB_PRIVKEY.into(), db_b.clone(), DB_KEY.into(), 2).unwrap();

        // Alice: mark events + register peer
        mark_event_processed(alice_pk.clone(), "evt-a1".into()).unwrap();
        mark_event_processed(alice_pk.clone(), "evt-a2".into()).unwrap();
        register_peer(
            alice_pk.clone(),
            "sig-peer-x".into(),
            "npub-x".into(),
            Some("inbox-x".into()),
        )
        .unwrap();

        // Bob: mark different events + register different peer
        mark_event_processed(bob_pk.clone(), "evt-b1".into()).unwrap();
        register_peer(
            bob_pk.clone(),
            "sig-peer-y".into(),
            "npub-y".into(),
            Some("inbox-y".into()),
        )
        .unwrap();

        eprintln!("✅ Phase 1: two identities initialized with state");
    }

    // Phase 2: "restart" — destroy all identities, re-init from same DBs
    {
        destroy_identity(alice_pk.clone()).unwrap();
        destroy_identity(bob_pk.clone()).unwrap();
        assert!(list_identities().unwrap().is_empty(), "all destroyed");

        // Re-init from the same DB files
        let alice_pk2 = init_v2(ALICE_PRIVKEY.into(), db_a.clone(), DB_KEY.into(), 1).unwrap();
        let bob_pk2 = init_v2(BOB_PRIVKEY.into(), db_b.clone(), DB_KEY.into(), 2).unwrap();

        // Pubkeys should be the same
        assert_eq!(alice_pk2, alice_pk, "Alice pubkey must be deterministic");
        assert_eq!(bob_pk2, bob_pk, "Bob pubkey must be deterministic");
        eprintln!("✅ Phase 2: re-initialized, pubkeys match");

        // Alice's state should be restored
        assert!(
            is_event_processed(alice_pk2.clone(), "evt-a1".into()).unwrap(),
            "Alice's evt-a1 must survive restart"
        );
        assert!(
            is_event_processed(alice_pk2.clone(), "evt-a2".into()).unwrap(),
            "Alice's evt-a2 must survive restart"
        );
        assert!(
            !is_event_processed(alice_pk2.clone(), "evt-b1".into()).unwrap(),
            "Alice should NOT have Bob's events"
        );
        assert_eq!(
            resolve_send_address(alice_pk2.clone(), "sig-peer-x".into()).unwrap(),
            "inbox-x",
            "Alice's peer address must survive restart"
        );
        eprintln!("✅ Alice's state fully restored from DB");

        // Bob's state should be restored
        assert!(
            is_event_processed(bob_pk2.clone(), "evt-b1".into()).unwrap(),
            "Bob's evt-b1 must survive restart"
        );
        assert!(
            !is_event_processed(bob_pk2.clone(), "evt-a1".into()).unwrap(),
            "Bob should NOT have Alice's events"
        );
        assert_eq!(
            resolve_send_address(bob_pk2.clone(), "sig-peer-y".into()).unwrap(),
            "inbox-y",
            "Bob's peer address must survive restart"
        );
        eprintln!("✅ Bob's state fully restored from DB");

        // Verify isolation still holds after restart
        assert!(resolve_send_address(alice_pk2.clone(), "sig-peer-y".into()).is_err());
        assert!(resolve_send_address(bob_pk2.clone(), "sig-peer-x".into()).is_err());
        eprintln!("✅ Isolation preserved after restart");

        destroy_identity(alice_pk2).unwrap();
        destroy_identity(bob_pk2).unwrap();
    }

    cleanup(&db_a);
    cleanup(&db_b);
}

// ─── Test 3: Init same identity twice is idempotent ─────────────────────────

#[test]
fn test_init_same_identity_twice() {
    let db = temp_db("idempotent");
    cleanup(&db);

    let pk1 = init_v2(ALICE_PRIVKEY.into(), db.clone(), DB_KEY.into(), 1).unwrap();
    mark_event_processed(pk1.clone(), "evt-1".into()).unwrap();

    // Init again with same privkey + same DB — should overwrite in-memory but DB state preserved
    let pk2 = init_v2(ALICE_PRIVKEY.into(), db.clone(), DB_KEY.into(), 1).unwrap();
    assert_eq!(pk1, pk2, "Same privkey produces same pubkey");

    // Event should survive because DB is the same
    assert!(
        is_event_processed(pk2.clone(), "evt-1".into()).unwrap(),
        "Event must survive re-init with same DB"
    );
    eprintln!("✅ Re-init same identity is idempotent, DB state preserved");

    destroy_identity(pk2).unwrap();
    cleanup(&db);
}

// ─── Helpers for Signal persistence ─────────────────────────────────────────

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

fn load_keys(db: &SecureStorage, peer_id: &str) -> (u32, SignalPreKeyMaterial) {
    let (dev_id, id_pub, id_priv, reg_id, spk_id, spk_rec, pk_id, pk_rec, kpk_id, kpk_rec) =
        db.load_signal_participant(peer_id).unwrap().unwrap();
    let identity_key = IdentityKey::decode(&id_pub).unwrap();
    let private_key = SignalPrivateKey::deserialize(&id_priv).unwrap();
    (
        dev_id,
        SignalPreKeyMaterial {
            identity_key_pair: IdentityKeyPair::new(identity_key, private_key),
            registration_id: reg_id,
            signed_prekey_id: SignedPreKeyId::from(spk_id),
            signed_prekey: SignedPreKeyRecord::deserialize(&spk_rec).unwrap(),
            prekey_id: PreKeyId::from(pk_id),
            prekey: PreKeyRecord::deserialize(&pk_rec).unwrap(),
            kyber_prekey_id: KyberPreKeyId::from(kpk_id),
            kyber_prekey: KyberPreKeyRecord::deserialize(&kpk_rec).unwrap(),
        },
    )
}

// ─── Test 4: Two identities, each with Signal session, persist independently ─

#[test]
fn test_multi_identity_signal_session_persistence() {
    let db_a = temp_db("sig_alice");
    let db_b = temp_db("sig_bob");
    cleanup(&db_a);
    cleanup(&db_b);

    // Alice talks to Tom, Bob talks to Jerry — two completely independent Signal sessions
    // Each identity has its own DB, its own persistent participant

    let alice_signal_id: String;
    let tom_signal_id: String;
    let bob_signal_id: String;
    let jerry_signal_id: String;

    // Phase 1: establish two independent sessions, exchange messages
    {
        let storage_a = Arc::new(Mutex::new(SecureStorage::open(&db_a, DB_KEY).unwrap()));
        let storage_b = Arc::new(Mutex::new(SecureStorage::open(&db_b, DB_KEY).unwrap()));

        let alice_keys = generate_prekey_material().unwrap();
        let bob_keys = generate_prekey_material().unwrap();

        // Alice (persistent) ↔ Tom (in-memory)
        let mut alice =
            SignalParticipant::persistent("alice".into(), 1, alice_keys.clone(), storage_a.clone())
                .unwrap();
        let mut tom = SignalParticipant::new("tom", 1).unwrap();

        alice_signal_id = alice.identity_public_key_hex();
        tom_signal_id = tom.identity_public_key_hex();

        let tom_bundle = tom.prekey_bundle().unwrap();
        let tom_addr = ProtocolAddress::new(tom_signal_id.clone(), DeviceId::new(1).unwrap());
        let alice_addr = ProtocolAddress::new(alice_signal_id.clone(), DeviceId::new(1).unwrap());

        alice.process_prekey_bundle(&tom_addr, &tom_bundle).unwrap();

        let ct = alice.encrypt(&tom_addr, b"Alice->Tom: hello").unwrap();
        let pt = tom.decrypt(&alice_addr, &ct.bytes).unwrap();
        assert_eq!(
            String::from_utf8(pt.plaintext).unwrap(),
            "Alice->Tom: hello"
        );

        // Direction change so ratchet advances
        let ct2 = tom.encrypt(&alice_addr, b"Tom->Alice: hi").unwrap();
        let pt2 = alice.decrypt(&tom_addr, &ct2.bytes).unwrap();
        assert_eq!(String::from_utf8(pt2.plaintext).unwrap(), "Tom->Alice: hi");

        save_keys(&storage_a.lock().unwrap(), &tom_signal_id, 1, &alice_keys);

        // Bob (persistent) ↔ Jerry (in-memory)
        let mut bob =
            SignalParticipant::persistent("bob".into(), 2, bob_keys.clone(), storage_b.clone())
                .unwrap();
        let mut jerry = SignalParticipant::new("jerry", 1).unwrap();

        bob_signal_id = bob.identity_public_key_hex();
        jerry_signal_id = jerry.identity_public_key_hex();

        let jerry_bundle = jerry.prekey_bundle().unwrap();
        let jerry_addr = ProtocolAddress::new(jerry_signal_id.clone(), DeviceId::new(1).unwrap());
        let bob_addr = ProtocolAddress::new(bob_signal_id.clone(), DeviceId::new(1).unwrap());

        bob.process_prekey_bundle(&jerry_addr, &jerry_bundle)
            .unwrap();

        let ct3 = bob.encrypt(&jerry_addr, b"Bob->Jerry: yo").unwrap();
        let pt3 = jerry.decrypt(&bob_addr, &ct3.bytes).unwrap();
        assert_eq!(String::from_utf8(pt3.plaintext).unwrap(), "Bob->Jerry: yo");

        let ct4 = jerry.encrypt(&bob_addr, b"Jerry->Bob: hey").unwrap();
        let pt4 = bob.decrypt(&jerry_addr, &ct4.bytes).unwrap();
        assert_eq!(String::from_utf8(pt4.plaintext).unwrap(), "Jerry->Bob: hey");

        save_keys(&storage_b.lock().unwrap(), &jerry_signal_id, 2, &bob_keys);

        eprintln!("✅ Phase 1: Alice↔Tom and Bob↔Jerry sessions established, 4 messages exchanged");
    }
    // All participants dropped — only DB files remain

    // Phase 2: restart both, verify identity keys restored independently
    {
        let storage_a = Arc::new(Mutex::new(SecureStorage::open(&db_a, DB_KEY).unwrap()));
        let storage_b = Arc::new(Mutex::new(SecureStorage::open(&db_b, DB_KEY).unwrap()));

        // Restore Alice
        let (dev_a, keys_a) = load_keys(&storage_a.lock().unwrap(), &tom_signal_id);
        assert_eq!(dev_a, 1);
        let alice_restored =
            SignalParticipant::persistent("alice".into(), dev_a, keys_a, storage_a.clone())
                .unwrap();
        assert_eq!(
            alice_restored.identity_public_key_hex(),
            alice_signal_id,
            "Alice identity key must survive restart"
        );

        // Restore Bob
        let (dev_b, keys_b) = load_keys(&storage_b.lock().unwrap(), &jerry_signal_id);
        assert_eq!(dev_b, 2);
        let bob_restored =
            SignalParticipant::persistent("bob".into(), dev_b, keys_b, storage_b.clone()).unwrap();
        assert_eq!(
            bob_restored.identity_public_key_hex(),
            bob_signal_id,
            "Bob identity key must survive restart"
        );

        // They should be completely different identities
        assert_ne!(
            alice_restored.identity_public_key_hex(),
            bob_restored.identity_public_key_hex(),
            "Alice and Bob must have different Signal identities"
        );

        // Verify DB isolation: Alice's DB should NOT contain Bob's participant
        assert!(
            storage_a
                .lock()
                .unwrap()
                .load_signal_participant(&jerry_signal_id)
                .unwrap()
                .is_none(),
            "Alice's DB must NOT contain Bob's peer (Jerry)"
        );
        assert!(
            storage_b
                .lock()
                .unwrap()
                .load_signal_participant(&tom_signal_id)
                .unwrap()
                .is_none(),
            "Bob's DB must NOT contain Alice's peer (Tom)"
        );

        eprintln!("✅ Phase 2: both identities restored, keys match, DBs isolated");
    }

    cleanup(&db_a);
    cleanup(&db_b);
}
