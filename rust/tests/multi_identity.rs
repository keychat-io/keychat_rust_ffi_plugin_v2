//! Multi-identity tests: verify multiple identities coexist and persist independently.

use keychat_rust_ffi_plugin_v2::api_v2::*;

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
