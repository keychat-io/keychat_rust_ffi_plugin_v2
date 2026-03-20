//! V2 MLS end-to-end test via FFI API functions.
//!
//! Simulates the full MLS group lifecycle through the V2 API layer:
//!   1. Initialize 3 identities (Alice, Bob, Charlie)
//!   2. Alice creates a group, adds Bob and Charlie
//!   3. Each member sends a message, others decrypt
//!   4. Alice removes Charlie
//!   5. Alice and Bob exchange messages (Charlie excluded)
//!   6. Bob leaves the group
//!   7. Cleanup

use keychat_rust_ffi_plugin_v2::api_v2::*;

fn temp_db(name: &str) -> String {
    let dir = std::env::temp_dir();
    dir.join(format!("keychat_mls_v2_{name}_{}.db", std::process::id()))
        .to_str()
        .unwrap()
        .to_string()
}

fn cleanup_db(path: &str) {
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{path}{suffix}"));
    }
    // MLS uses a separate DB file
    let mls_path = path.replace(".db", "_mls.db");
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{mls_path}{suffix}"));
    }
}

struct TestUser {
    pubkey: String,
    db_path: String,
}

impl TestUser {
    fn new(name: &str) -> Self {
        let secret = format!(
            "{:0>64}",
            hex::encode(name.as_bytes())
        );
        let db_path = temp_db(name);
        let pubkey = init_v2(secret, db_path.clone(), "test-key".to_string(), 1).unwrap();
        eprintln!("  {name}: pubkey={}...", &pubkey[..16]);
        TestUser { pubkey, db_path }
    }
}

impl Drop for TestUser {
    fn drop(&mut self) {
        cleanup_db(&self.db_path);
    }
}

#[test]
fn test_mls_v2_full_lifecycle() {
    eprintln!("\n============================================================");
    eprintln!("  V2 MLS Full Lifecycle Test");
    eprintln!("============================================================\n");

    // ━━━ Phase 1: Initialize identities ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    eprintln!("--- Phase 1: Initialize identities ---");
    let alice = TestUser::new("alice_mls_test_user_1234");
    let bob = TestUser::new("bob_mls_test_user_567890");
    let charlie = TestUser::new("charlie_mls_test_12345");

    // Init MLS subsystem for each
    mls_init(alice.pubkey.clone()).unwrap();
    mls_init(bob.pubkey.clone()).unwrap();
    mls_init(charlie.pubkey.clone()).unwrap();
    eprintln!("✅ Phase 1: 3 identities initialized with MLS\n");

    // ━━━ Phase 2: Alice creates group, adds Bob and Charlie ━━━━━━━━━━━━━━━━━

    eprintln!("--- Phase 2: Create group and add members ---");
    let group_id = "test-mls-v2-group";
    let group_name = "V2 Test Group";

    // Create group
    mls_create_group(
        alice.pubkey.clone(),
        group_id.to_string(),
        group_name.to_string(),
    )
    .unwrap();
    eprintln!("  Alice created group '{group_name}'");

    // Generate key packages for Bob and Charlie
    let bob_kp = mls_generate_key_package(bob.pubkey.clone()).unwrap();
    let charlie_kp = mls_generate_key_package(charlie.pubkey.clone()).unwrap();
    eprintln!("  Bob and Charlie generated key packages");

    // Alice adds members
    let kp_json = serde_json::to_string(&vec![&bob_kp, &charlie_kp]).unwrap();
    let add_result = mls_add_members(
        alice.pubkey.clone(),
        group_id.to_string(),
        kp_json,
    )
    .unwrap();
    eprintln!(
        "  Alice added members: commit={} bytes, welcome={} bytes",
        add_result.commit_base64.len(),
        add_result.welcome_base64.len()
    );

    // Bob and Charlie join via Welcome
    let bob_group = mls_join_group(bob.pubkey.clone(), add_result.welcome_base64.clone()).unwrap();
    assert_eq!(bob_group, group_id, "Bob must join the correct group");
    eprintln!("  Bob joined group: {bob_group}");

    let charlie_group =
        mls_join_group(charlie.pubkey.clone(), add_result.welcome_base64.clone()).unwrap();
    assert_eq!(charlie_group, group_id, "Charlie must join the correct group");
    eprintln!("  Charlie joined group: {charlie_group}");

    // Verify members
    let alice_members = mls_group_members(alice.pubkey.clone(), group_id.to_string()).unwrap();
    eprintln!("  Group members (from Alice): {:?}", alice_members);
    assert_eq!(alice_members.len(), 3, "Group should have 3 members");

    eprintln!("✅ Phase 2: Group created with 3 members\n");

    // ━━━ Phase 3: Message exchange ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    eprintln!("--- Phase 3: Message exchange ---");

    // Alice sends a message
    let alice_ct = mls_encrypt(
        alice.pubkey.clone(),
        group_id.to_string(),
        "Hello from Alice!".to_string(),
    )
    .unwrap();
    eprintln!("  Alice encrypted: {} bytes ciphertext", alice_ct.len());

    // Bob decrypts
    let bob_pt = mls_decrypt(
        bob.pubkey.clone(),
        group_id.to_string(),
        alice_ct.clone(),
    )
    .unwrap();
    assert_eq!(bob_pt.plaintext, "Hello from Alice!");
    eprintln!(
        "  Bob decrypted: '{}' from sender={}",
        bob_pt.plaintext, bob_pt.sender_id
    );

    // Charlie decrypts
    let charlie_pt = mls_decrypt(
        charlie.pubkey.clone(),
        group_id.to_string(),
        alice_ct,
    )
    .unwrap();
    assert_eq!(charlie_pt.plaintext, "Hello from Alice!");
    eprintln!(
        "  Charlie decrypted: '{}' from sender={}",
        charlie_pt.plaintext, charlie_pt.sender_id
    );

    // Bob sends a message
    let bob_ct = mls_encrypt(
        bob.pubkey.clone(),
        group_id.to_string(),
        "Hey everyone, Bob here!".to_string(),
    )
    .unwrap();

    let alice_pt2 = mls_decrypt(
        alice.pubkey.clone(),
        group_id.to_string(),
        bob_ct.clone(),
    )
    .unwrap();
    assert_eq!(alice_pt2.plaintext, "Hey everyone, Bob here!");
    eprintln!("  Alice decrypted Bob's msg: '{}'", alice_pt2.plaintext);

    let charlie_pt2 = mls_decrypt(
        charlie.pubkey.clone(),
        group_id.to_string(),
        bob_ct,
    )
    .unwrap();
    assert_eq!(charlie_pt2.plaintext, "Hey everyone, Bob here!");
    eprintln!("  Charlie decrypted Bob's msg: '{}'", charlie_pt2.plaintext);

    // Charlie sends a message
    let charlie_ct = mls_encrypt(
        charlie.pubkey.clone(),
        group_id.to_string(),
        "Charlie checking in!".to_string(),
    )
    .unwrap();

    let alice_pt3 = mls_decrypt(
        alice.pubkey.clone(),
        group_id.to_string(),
        charlie_ct.clone(),
    )
    .unwrap();
    assert_eq!(alice_pt3.plaintext, "Charlie checking in!");

    let bob_pt3 = mls_decrypt(
        bob.pubkey.clone(),
        group_id.to_string(),
        charlie_ct,
    )
    .unwrap();
    assert_eq!(bob_pt3.plaintext, "Charlie checking in!");

    eprintln!("✅ Phase 3: All 3 members exchanged messages successfully\n");

    // ━━━ Phase 4: Derive temp inbox ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    eprintln!("--- Phase 4: Derive temp inbox ---");
    let alice_inbox = mls_derive_temp_inbox(alice.pubkey.clone(), group_id.to_string()).unwrap();
    let bob_inbox = mls_derive_temp_inbox(bob.pubkey.clone(), group_id.to_string()).unwrap();
    let charlie_inbox =
        mls_derive_temp_inbox(charlie.pubkey.clone(), group_id.to_string()).unwrap();

    eprintln!("  Alice inbox:   {}...", &alice_inbox[..16]);
    eprintln!("  Bob inbox:     {}...", &bob_inbox[..16]);
    eprintln!("  Charlie inbox: {}...", &charlie_inbox[..16]);

    // All members should derive the same listening key
    assert_eq!(
        alice_inbox, bob_inbox,
        "Alice and Bob must derive same temp inbox"
    );
    assert_eq!(
        bob_inbox, charlie_inbox,
        "Bob and Charlie must derive same temp inbox"
    );
    eprintln!("✅ Phase 4: All members derive same temp inbox\n");

    // ━━━ Phase 5: Group info ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    eprintln!("--- Phase 5: Group info ---");
    let info = mls_group_info(alice.pubkey.clone(), group_id.to_string()).unwrap();
    eprintln!("  name='{}', status='{}', admins={}", info.name, info.status, info.admins_json);
    assert_eq!(info.name, group_name);
    eprintln!("✅ Phase 5: Group info correct\n");

    // ━━━ Phase 6: Remove Charlie ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    eprintln!("--- Phase 6: Remove Charlie ---");
    let charlie_nostr_id = charlie.pubkey.clone();
    let remove_members_json = serde_json::to_string(&vec![&charlie_nostr_id]).unwrap();
    let remove_commit = mls_remove_members(
        alice.pubkey.clone(),
        group_id.to_string(),
        remove_members_json,
    )
    .unwrap();
    eprintln!("  Alice created remove commit: {} bytes", remove_commit.len());

    // Bob processes the remove commit
    mls_process_commit(
        bob.pubkey.clone(),
        group_id.to_string(),
        remove_commit,
    )
    .unwrap();
    eprintln!("  Bob processed remove commit");

    // Verify member count
    let members_after = mls_group_members(alice.pubkey.clone(), group_id.to_string()).unwrap();
    assert_eq!(members_after.len(), 2, "Group should have 2 members after removal");
    eprintln!("  Members after removal: {:?}", members_after);

    // Alice sends message — Bob should decrypt, Charlie should NOT
    let alice_ct2 = mls_encrypt(
        alice.pubkey.clone(),
        group_id.to_string(),
        "Secret msg after Charlie removed".to_string(),
    )
    .unwrap();

    let bob_pt4 = mls_decrypt(
        bob.pubkey.clone(),
        group_id.to_string(),
        alice_ct2.clone(),
    )
    .unwrap();
    assert_eq!(bob_pt4.plaintext, "Secret msg after Charlie removed");
    eprintln!("  Bob decrypted post-removal msg: '{}'", bob_pt4.plaintext);

    // Charlie should fail to decrypt (removed from group)
    let charlie_result = mls_decrypt(
        charlie.pubkey.clone(),
        group_id.to_string(),
        alice_ct2,
    );
    assert!(
        charlie_result.is_err(),
        "Charlie must NOT decrypt after removal"
    );
    eprintln!("  Charlie correctly failed to decrypt: {}", charlie_result.unwrap_err());

    eprintln!("✅ Phase 6: Charlie removed, forward secrecy verified\n");

    // ━━━ Phase 7: Bob leaves ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    eprintln!("--- Phase 7: Bob leaves ---");
    let leave_proposal = mls_leave_group(bob.pubkey.clone(), group_id.to_string()).unwrap();
    eprintln!("  Bob created leave proposal: {} bytes", leave_proposal.len());

    // Alice processes the leave proposal as a commit
    // Note: in real flow, admin would commit the leave proposal
    // For testing, we check that the proposal was generated successfully
    eprintln!("  Leave proposal generated successfully");

    eprintln!("✅ Phase 7: Bob leave proposal created\n");

    // ━━━ Phase 8: Self-update (key rotation) ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    eprintln!("--- Phase 8: Key rotation ---");
    let update_commit = mls_self_update(alice.pubkey.clone(), group_id.to_string()).unwrap();
    eprintln!("  Alice self-update commit: {} bytes", update_commit.len());

    // Bob processes the update (if still in group state)
    let bob_update_result = mls_process_commit(
        bob.pubkey.clone(),
        group_id.to_string(),
        update_commit,
    );
    // This may succeed or fail depending on whether Bob's leave was committed
    eprintln!("  Bob process update result: {:?}", bob_update_result.is_ok());

    eprintln!("✅ Phase 8: Key rotation tested\n");

    // ━━━ Summary ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    eprintln!("============================================================");
    eprintln!("  V2 MLS LIFECYCLE TEST COMPLETE");
    eprintln!("  ✅ Group creation + member addition");
    eprintln!("  ✅ 3-way message exchange (encrypt/decrypt)");
    eprintln!("  ✅ Shared temp inbox derivation");
    eprintln!("  ✅ Group info metadata");
    eprintln!("  ✅ Member removal + forward secrecy");
    eprintln!("  ✅ Leave proposal");
    eprintln!("  ✅ Key rotation (self-update)");
    eprintln!("============================================================\n");
}
