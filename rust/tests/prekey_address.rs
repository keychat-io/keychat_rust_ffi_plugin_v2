//! Test: verify addresses returned after PreKey message decrypt and subsequent encrypt.
//!
//! Simulates the V2 friend request flow:
//!   1. Alice creates Signal participant, generates prekey bundle
//!   2. Bob processes Alice's bundle (PQXDH), encrypts first message (PreKeyMessage)
//!   3. Alice decrypts PreKeyMessage → check bob_derived_address
//!   4. Alice encrypts a reply → check sender_address
//!   5. Bob decrypts Alice's reply → check bob_derived_address

use libkeychat::{DeviceId, ProtocolAddress, SignalParticipant};

#[test]
fn test_prekey_decrypt_address_fields() {
    eprintln!("\n=== PreKey Address Fields Test ===\n");

    // Create Alice (the friend request sender / bundle provider)
    let mut alice = SignalParticipant::new("alice", 1).unwrap();
    let alice_id = alice.identity_public_key_hex();
    eprintln!("Alice signal_id: {}...", &alice_id[..16]);

    // Create Bob (the accepter who processes Alice's bundle)
    let mut bob = SignalParticipant::new("bob", 1).unwrap();
    let bob_id = bob.identity_public_key_hex();
    eprintln!("Bob   signal_id: {}...", &bob_id[..16]);

    let alice_addr = ProtocolAddress::new(alice_id.clone(), DeviceId::new(1).unwrap());
    let bob_addr = ProtocolAddress::new(bob_id.clone(), DeviceId::new(1).unwrap());

    // Step 1: Bob processes Alice's prekey bundle (like accept_friend_request)
    let alice_bundle = alice.prekey_bundle().unwrap();
    bob.process_prekey_bundle(&alice_addr, &alice_bundle).unwrap();
    eprintln!("✅ Bob processed Alice's prekey bundle");

    // Step 2: Bob encrypts first message (PreKeyMessage) → sent to Alice
    let bob_ct = bob.encrypt(&alice_addr, b"approve message from bob").unwrap();
    eprintln!(
        "Bob encrypt: sender_address={:?}",
        bob_ct.sender_address
    );

    // Step 3: Alice decrypts PreKeyMessage → THIS is what complete_friend_request does
    let alice_decrypt = alice.decrypt(&bob_addr, &bob_ct.bytes).unwrap();
    let plaintext = String::from_utf8(alice_decrypt.plaintext).unwrap();
    assert_eq!(plaintext, "approve message from bob");

    eprintln!(
        "\n--- Alice decrypt PreKeyMessage results ---"
    );
    eprintln!(
        "  bob_derived_address: {:?}",
        alice_decrypt.bob_derived_address
    );
    eprintln!(
        "  alice_addrs:         {:?}",
        alice_decrypt.alice_addrs
    );

    // This is the key assertion: does bob_derived_address have a value?
    if alice_decrypt.bob_derived_address.is_some() {
        eprintln!("  ✅ bob_derived_address has value → on_decrypt can set sending_address");
    } else {
        eprintln!("  ❌ bob_derived_address is None → on_decrypt won't set sending_address");
    }

    // Step 4: Alice encrypts a reply → check sender_address (ratchet-derived)
    let alice_ct = alice.encrypt(&bob_addr, b"hello from alice").unwrap();
    eprintln!(
        "\n--- Alice encrypt (after PreKey decrypt) ---"
    );
    eprintln!(
        "  sender_address: {:?}",
        alice_ct.sender_address
    );

    // Step 5: Bob decrypts Alice's reply
    let bob_decrypt = bob.decrypt(&alice_addr, &alice_ct.bytes).unwrap();
    let pt2 = String::from_utf8(bob_decrypt.plaintext).unwrap();
    assert_eq!(pt2, "hello from alice");

    eprintln!(
        "\n--- Bob decrypt Alice's reply ---"
    );
    eprintln!(
        "  bob_derived_address: {:?}",
        bob_decrypt.bob_derived_address
    );
    eprintln!(
        "  alice_addrs:         {:?}",
        bob_decrypt.alice_addrs
    );

    // Step 6: Bob encrypts another message → check if ratchet address advances
    let bob_ct2 = bob.encrypt(&alice_addr, b"second message from bob").unwrap();
    eprintln!(
        "\n--- Bob encrypt (round 2) ---"
    );
    eprintln!(
        "  sender_address: {:?}",
        bob_ct2.sender_address
    );

    let alice_decrypt2 = alice.decrypt(&bob_addr, &bob_ct2.bytes).unwrap();
    eprintln!(
        "\n--- Alice decrypt (round 2) ---"
    );
    eprintln!(
        "  bob_derived_address: {:?}",
        alice_decrypt2.bob_derived_address
    );
    eprintln!(
        "  alice_addrs:         {:?}",
        alice_decrypt2.alice_addrs
    );

    eprintln!("\n=== Test Complete ===\n");
}
