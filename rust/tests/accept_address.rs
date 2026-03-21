//! Test: verify Bob gets new receiving addresses after accepting a friend request.
//!
//! End-to-end FFI test:
//!   1. Alice calls create_friend_request → sends event to Bob
//!   2. Bob calls accept_friend_request → creates prekey message
//!   3. Verify Bob's V2AcceptResult.new_receiving_addresses is non-empty
//!   4. Verify get_all_receiving_addresses also returns those addresses

use keychat_rust_ffi_plugin_v2::api_v2::*;
use std::env;

/// Generate a unique temp DB path to avoid cross-test conflicts.
fn temp_db(label: &str) -> String {
    let pid = std::process::id();
    let dir = env::temp_dir();
    format!("{}/keychat_accept_addr_{}_{}.db", dir.display(), label, pid)
}

#[test]
fn test_accept_friend_request_returns_receiving_addresses() {
    eprintln!("\n=== Accept Friend Request Address Test ===\n");

    // Init Alice
    let alice_priv = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
    let alice_pub = init_v2(
        alice_priv.into(),
        temp_db("alice"),
        "test-key".into(),
        1,
    )
    .expect("Alice init_v2 failed");
    eprintln!("Alice pubkey: {}...", &alice_pub[..16]);

    // Init Bob
    let bob_priv = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
    let bob_pub = init_v2(
        bob_priv.into(),
        temp_db("bob"),
        "test-key".into(),
        1,
    )
    .expect("Bob init_v2 failed");
    eprintln!("Bob   pubkey: {}...", &bob_pub[..16]);

    // Step 1: Alice creates friend request to Bob
    let fr = create_friend_request(alice_pub.clone(), bob_pub.clone(), "Alice".into())
        .expect("create_friend_request failed");
    eprintln!(
        "Alice created friend request: signal_id={}..., firstInbox={}...",
        &fr.signal_identity_hex[..16],
        &fr.first_inbox_pubkey[..16]
    );

    // Step 2: Bob accepts the friend request (creates prekey message)
    let accept = accept_friend_request(bob_pub.clone(), fr.event_json.clone(), "Bob".into())
        .expect("accept_friend_request failed");
    eprintln!(
        "Bob accepted: peerSignalId={}..., new_receiving_addresses={}",
        &accept.peer_signal_identity[..16],
        accept.new_receiving_addresses.len()
    );

    // KEY ASSERTION: Bob must get at least 1 receiving address after accept
    assert!(
        !accept.new_receiving_addresses.is_empty(),
        "Bob should get new receiving addresses after accepting (creating prekey message), got 0"
    );

    for (i, addr) in accept.new_receiving_addresses.iter().enumerate() {
        eprintln!("  Bob receiving addr[{}]: {}...", i, &addr[..16.min(addr.len())]);
    }

    // Verify get_all_receiving_addresses returns the same addresses
    let all_addrs = get_all_receiving_addresses(bob_pub.clone(), accept.peer_signal_identity.clone())
        .expect("get_all_receiving_addresses failed");
    eprintln!("Bob get_all_receiving_addresses: {} addrs", all_addrs.len());

    assert!(
        !all_addrs.is_empty(),
        "get_all_receiving_addresses should also return addresses"
    );

    // All addresses from accept should be in the full list
    for addr in &accept.new_receiving_addresses {
        assert!(
            all_addrs.contains(addr),
            "Address from accept result not found in get_all_receiving_addresses: {}",
            addr
        );
    }

    eprintln!("\n✅ Bob got {} receiving addresses after accepting friend request", accept.new_receiving_addresses.len());
    eprintln!("=== Test Complete ===\n");
}
