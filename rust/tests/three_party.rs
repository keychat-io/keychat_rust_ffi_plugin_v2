//! Three-party end-to-end test:
//!   1. Alice, Tom, Bob — each pair adds friend via Signal (6 sessions total)
//!   2. Each person sends a message to each other → decrypt succeeds
//!   3. Alice creates an MLS group, adds Tom and Bob
//!   4. Each member sends a group message → other two decrypt it

use libkeychat::{
    DeviceId, MlsParticipant, ProtocolAddress, SignalParticipant,
};

// ─── Helpers ────────────────────────────────────────────────────────────────

/// A test user with a Signal participant for each peer.
struct User {
    name: String,
    /// Signal sessions keyed by peer signal_id
    sessions: Vec<(String, SignalParticipant)>,
    /// MLS participant
    mls: MlsParticipant,
    /// This user's signal identity hex (from the first session created)
    signal_id: String,
}

/// Create a Signal participant for a user and return (signal_identity_hex, participant).
fn make_signal(name: &str) -> (String, SignalParticipant) {
    let p = SignalParticipant::new(name, 1).unwrap();
    let id = p.identity_public_key_hex();
    (id, p)
}

/// Establish a two-way Signal session between two participants.
/// Returns the ProtocolAddresses for (a→b, b→a).
fn establish_session(
    a: &mut SignalParticipant,
    a_id: &str,
    b: &mut SignalParticipant,
    b_id: &str,
) -> (ProtocolAddress, ProtocolAddress) {
    let b_bundle = b.prekey_bundle().unwrap();
    let b_addr = ProtocolAddress::new(b_id.to_string(), DeviceId::new(1).unwrap());
    let a_addr = ProtocolAddress::new(a_id.to_string(), DeviceId::new(1).unwrap());

    a.process_prekey_bundle(&b_addr, &b_bundle).unwrap();

    // Alice sends a handshake message so Bob's session is also initialized
    let ct = a.encrypt(&b_addr, b"__handshake__").unwrap();
    let pt = b.decrypt(&a_addr, &ct.bytes).unwrap();
    assert_eq!(String::from_utf8(pt.plaintext).unwrap(), "__handshake__");

    (b_addr, a_addr)
}

/// Encrypt a message, decrypt it, and verify the plaintext matches.
fn send_and_verify(
    sender: &mut SignalParticipant,
    receiver: &mut SignalParticipant,
    sender_to_receiver_addr: &ProtocolAddress,
    receiver_to_sender_addr: &ProtocolAddress,
    message: &str,
) {
    let ct = sender
        .encrypt(sender_to_receiver_addr, message.as_bytes())
        .unwrap();
    let pt = receiver
        .decrypt(receiver_to_sender_addr, &ct.bytes)
        .unwrap();
    let decrypted = String::from_utf8(pt.plaintext).unwrap();
    assert_eq!(decrypted, message, "decrypted text must match original");
}

// ─── Main Test ──────────────────────────────────────────────────────────────

#[test]
fn test_three_party_signal_and_mls() {
    eprintln!("\n============================================================");
    eprintln!("  Three-Party Signal + MLS End-to-End Test");
    eprintln!("============================================================\n");

    // ━━━ Part 1: Create three users' Signal identities ━━━━━━━━━━━━━━━━━━━━━

    // Each pair needs separate SignalParticipant instances because each
    // session has its own key material. So Alice has 2 participants:
    //   alice_for_tom  — session with Tom
    //   alice_for_bob  — session with Bob

    let (alice_tom_id, mut alice_for_tom) = make_signal("alice_tom");
    let (alice_bob_id, mut alice_for_bob) = make_signal("alice_bob");
    let (tom_alice_id, mut tom_for_alice) = make_signal("tom_alice");
    let (tom_bob_id, mut tom_for_bob) = make_signal("tom_bob");
    let (bob_alice_id, mut bob_for_alice) = make_signal("bob_alice");
    let (bob_tom_id, mut bob_for_tom) = make_signal("bob_tom");

    eprintln!("✅ Created 6 Signal identities (2 per user, 1 per peer)");
    eprintln!("   Alice: {} / {}", &alice_tom_id[..12], &alice_bob_id[..12]);
    eprintln!("   Tom:   {} / {}", &tom_alice_id[..12], &tom_bob_id[..12]);
    eprintln!("   Bob:   {} / {}", &bob_alice_id[..12], &bob_tom_id[..12]);

    // ━━━ Part 2: Establish all 3 Signal sessions (add friend) ━━━━━━━━━━━━━━

    // Alice ↔ Tom
    let (alice_to_tom_addr, tom_to_alice_addr) = establish_session(
        &mut alice_for_tom, &alice_tom_id,
        &mut tom_for_alice, &tom_alice_id,
    );
    eprintln!("✅ Session established: Alice ↔ Tom");

    // Alice ↔ Bob
    let (alice_to_bob_addr, bob_to_alice_addr) = establish_session(
        &mut alice_for_bob, &alice_bob_id,
        &mut bob_for_alice, &bob_alice_id,
    );
    eprintln!("✅ Session established: Alice ↔ Bob");

    // Tom ↔ Bob
    let (tom_to_bob_addr, bob_to_tom_addr) = establish_session(
        &mut tom_for_bob, &tom_bob_id,
        &mut bob_for_tom, &bob_tom_id,
    );
    eprintln!("✅ Session established: Tom ↔ Bob");

    // ━━━ Part 3: Each person sends a message to each other ━━━━━━━━━━━━━━━━━

    // Alice → Tom
    send_and_verify(
        &mut alice_for_tom, &mut tom_for_alice,
        &alice_to_tom_addr, &tom_to_alice_addr,
        "Hi Tom, this is Alice!",
    );
    eprintln!("✅ Alice → Tom: 'Hi Tom, this is Alice!'");

    // Tom → Alice
    send_and_verify(
        &mut tom_for_alice, &mut alice_for_tom,
        &tom_to_alice_addr, &alice_to_tom_addr,
        "Hey Alice, Tom here!",
    );
    eprintln!("✅ Tom → Alice: 'Hey Alice, Tom here!'");

    // Alice → Bob
    send_and_verify(
        &mut alice_for_bob, &mut bob_for_alice,
        &alice_to_bob_addr, &bob_to_alice_addr,
        "Hello Bob, from Alice",
    );
    eprintln!("✅ Alice → Bob: 'Hello Bob, from Alice'");

    // Bob → Alice
    send_and_verify(
        &mut bob_for_alice, &mut alice_for_bob,
        &bob_to_alice_addr, &alice_to_bob_addr,
        "Hi Alice, Bob speaking",
    );
    eprintln!("✅ Bob → Alice: 'Hi Alice, Bob speaking'");

    // Tom → Bob
    send_and_verify(
        &mut tom_for_bob, &mut bob_for_tom,
        &tom_to_bob_addr, &bob_to_tom_addr,
        "Bob, this is Tom!",
    );
    eprintln!("✅ Tom → Bob: 'Bob, this is Tom!'");

    // Bob → Tom
    send_and_verify(
        &mut bob_for_tom, &mut tom_for_bob,
        &bob_to_tom_addr, &tom_to_bob_addr,
        "Tom, Bob here. Received!",
    );
    eprintln!("✅ Bob → Tom: 'Tom, Bob here. Received!'");

    eprintln!("\n--- Signal 1:1 messaging complete (6 messages, all decrypted) ---\n");

    // ━━━ Part 4: MLS Group — Alice creates, adds Tom and Bob ━━━━━━━━━━━━━━━

    let alice_mls = MlsParticipant::new("alice_nostr_pub");
    let tom_mls = MlsParticipant::new("tom_nostr_pub");
    let bob_mls = MlsParticipant::new("bob_nostr_pub");

    let group_id = "test-group-3party";

    // Alice creates the group
    alice_mls.create_group(group_id, "Three Amigos").unwrap();
    eprintln!("✅ Alice created MLS group '{group_id}'");

    // Tom and Bob generate KeyPackages
    let tom_kp = tom_mls.generate_key_package().unwrap();
    let bob_kp = bob_mls.generate_key_package().unwrap();

    // Alice adds Tom and Bob
    let (commit_bytes, welcome_bytes) = alice_mls
        .add_members(group_id, vec![tom_kp, bob_kp])
        .unwrap();
    eprintln!("✅ Alice added Tom and Bob to group");

    // Tom and Bob join via Welcome
    let tom_group_id = tom_mls.join_group(&welcome_bytes).unwrap();
    let bob_group_id = bob_mls.join_group(&welcome_bytes).unwrap();
    assert_eq!(tom_group_id, group_id);
    assert_eq!(bob_group_id, group_id);
    eprintln!("✅ Tom and Bob joined the group via Welcome");

    // Verify members
    let members = alice_mls.group_members(group_id).unwrap();
    assert_eq!(members.len(), 3, "Group should have 3 members");
    eprintln!("✅ Group members: {:?}", members);

    // ━━━ Part 5: MLS Group messaging — each sends, others decrypt ━━━━━━━━━━

    // Alice sends to group
    let alice_ct = alice_mls.encrypt(group_id, b"Group msg from Alice").unwrap();

    let (tom_pt, tom_sender) = tom_mls.decrypt(group_id, &alice_ct).unwrap();
    assert_eq!(String::from_utf8(tom_pt).unwrap(), "Group msg from Alice");
    assert_eq!(tom_sender, "alice_nostr_pub");

    let (bob_pt, bob_sender) = bob_mls.decrypt(group_id, &alice_ct).unwrap();
    assert_eq!(String::from_utf8(bob_pt).unwrap(), "Group msg from Alice");
    assert_eq!(bob_sender, "alice_nostr_pub");

    eprintln!("✅ Alice → Group: Tom and Bob both decrypted successfully");

    // Tom sends to group
    let tom_ct = tom_mls.encrypt(group_id, b"Group msg from Tom").unwrap();

    let (alice_pt2, alice_sender2) = alice_mls.decrypt(group_id, &tom_ct).unwrap();
    assert_eq!(String::from_utf8(alice_pt2).unwrap(), "Group msg from Tom");
    assert_eq!(alice_sender2, "tom_nostr_pub");

    let (bob_pt2, bob_sender2) = bob_mls.decrypt(group_id, &tom_ct).unwrap();
    assert_eq!(String::from_utf8(bob_pt2).unwrap(), "Group msg from Tom");
    assert_eq!(bob_sender2, "tom_nostr_pub");

    eprintln!("✅ Tom → Group: Alice and Bob both decrypted successfully");

    // Bob sends to group
    let bob_ct = bob_mls.encrypt(group_id, b"Group msg from Bob").unwrap();

    let (alice_pt3, alice_sender3) = alice_mls.decrypt(group_id, &bob_ct).unwrap();
    assert_eq!(String::from_utf8(alice_pt3).unwrap(), "Group msg from Bob");
    assert_eq!(alice_sender3, "bob_nostr_pub");

    let (tom_pt3, tom_sender3) = tom_mls.decrypt(group_id, &bob_ct).unwrap();
    assert_eq!(String::from_utf8(tom_pt3).unwrap(), "Group msg from Bob");
    assert_eq!(tom_sender3, "bob_nostr_pub");

    eprintln!("✅ Bob → Group: Alice and Tom both decrypted successfully");

    // ━━━ Summary ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    eprintln!("\n============================================================");
    eprintln!("  ALL PASSED");
    eprintln!("  Signal: 3 pairs × 2 directions = 6 messages ✅");
    eprintln!("  MLS:    3 members × 1 group msg each = 3 msgs, 6 decrypts ✅");
    eprintln!("============================================================\n");
}
