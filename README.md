# keychat_rust_ffi_plugin_v2

Flutter FFI plugin for Keychat Protocol V2.

Wraps [libkeychat](https://github.com/keychat-io/keychat-protocol) — Signal PQXDH + MLS + SQLCipher persistent storage.

## Architecture

```
keychat_rust_ffi_plugin      (V1: Signal X3DH, MLS kc4, CDK kc2)
keychat_rust_ffi_plugin_v2   (V2: Signal PQXDH + MLS RFC9420 via libkeychat, SQLCipher storage)
```

Two independent Rust projects, two independent dependency trees, zero conflicts.

## Multi-Identity

Supports multiple Nostr identities running simultaneously. Each identity has its own isolated state (Signal sessions, MLS groups, peers, events). All stateful APIs take `pubkey` as the first parameter to select which identity to operate on.

```
App
├── Identity A (pubkey_a) → DB_A.db  (Signal sessions, MLS groups, peers)
├── Identity B (pubkey_b) → DB_B.db  (completely independent)
└── Identity C (pubkey_c) → DB_C.db
```

## V2 API

> All stateful functions take `pubkey: String` as first parameter (returned by `initV2`).
> Functions marked with * are stateless and don't need `pubkey`.

### Identity Lifecycle

| Function | Description |
|----------|-------------|
| `initV2(nostrPrivkeyHex, dbPath, dbKey, deviceId) -> pubkey` | Initialize identity, returns pubkey hex for subsequent calls |
| `destroyIdentity(pubkey)` | Destroy an identity and release resources |
| `listIdentities()` | List all active identity pubkeys |
| `getDeviceId(pubkey)` | Get device ID for an identity |

### Signal 1:1 Messaging

| Function | Description |
|----------|-------------|
| `createFriendRequest(pubkey, peerNpub, displayName)` | Send PQXDH friend request (kind:1059) |
| `receiveFriendRequest(pubkey, eventJson)` | Parse incoming friend request |
| `acceptFriendRequest(pubkey, eventJson, displayName)` | Accept and establish Signal session |
| `encrypt(pubkey, peerSignalId, plaintext, remoteDeviceId)` | Signal PQXDH encrypt |
| `decrypt(pubkey, peerSignalId, ciphertextBase64, remoteDeviceId)` | Signal PQXDH decrypt |

### MLS Group Messaging (RFC 9420)

| Function | Description |
|----------|-------------|
| `mlsInit(pubkey)` | Initialize MLS subsystem (file-backed storage) |
| `mlsCreateGroup(pubkey, groupId, name)` | Create MLS group |
| `mlsAddMembers(pubkey, groupId, keyPackagesJson)` | Add members, returns commit + welcome |
| `mlsJoinGroup(pubkey, welcomeBase64)` | Join group via Welcome |
| `mlsEncrypt(pubkey, groupId, plaintext)` / `mlsDecrypt(pubkey, groupId, ct)` | Group encrypt/decrypt |
| `mlsGroupMembers(pubkey, groupId)` | List group members |
| `mlsRemoveMembers` / `mlsSelfUpdate` / `mlsLeaveGroup` | Group management |
| `mlsProcessCommit` / `mlsUpdateGroup` / `mlsGroupInfo` | Commit processing + metadata |
| `mlsGenerateKeyPackage(pubkey)` | Generate KeyPackage for group invitation |
| `mlsDeriveTempInbox(pubkey, groupId)` | Derive shared temp inbox address |

### Relay Transport

| Function | Description |
|----------|-------------|
| `relayConnect(pubkey, relayUrlsJson)` | Connect to Nostr relays |
| `relaySubscribe(pubkey, pubkeysJson, sinceTimestamp)` | Subscribe to kind:1059 events |
| `relayNextEvent(pubkey)` | Fetch next event (non-blocking) |
| `relayNextEventBlocking(pubkey, timeoutMs)` | Fetch next event (blocking with timeout) |
| `relayPublish(pubkey, eventJson)` | Broadcast event to all relays |
| `relayDisconnect(pubkey)` | Disconnect from relays |
| `relayIsConnected(pubkey)` | Check connection status |

### Gift Wrap & Stamp

| Function | Description |
|----------|-------------|
| `wrapEvent(pubkey, innerContent, receiverNpub)` | Kind:1059 Gift Wrap |
| `unwrapEvent(pubkey, eventJson)` | Unwrap Gift Wrap |
| `fetchRelayFees(pubkey, relayUrl)` | NIP-11 relay fee discovery |
| `stampEvent(eventJson, cashuToken)` * | Attach ecash stamp |

### KCMessage V2

| Function | Description |
|----------|-------------|
| `buildTextMessage(text)` * | Build text KCMessage v2 |
| `buildFriendRequestMessage(payloadJson)` * | Build friend request payload |
| `parseMessage(json)` * | Parse KCMessage v2 |

### Peer & Address Management

| Function | Description |
|----------|-------------|
| `registerPeer(pubkey, peerSignalId, peerNpub, firstInbox)` | Register peer address state |
| `resolveSendAddress(pubkey, peerSignalId)` | Resolve send address (ratchet > inbox > npub) |
| `getAllReceivingAddresses(pubkey, peerSignalId)` | Get receiving addresses for a peer |
| `deriveReceivingAddress(privateKeyHex, publicKeyHex)` * | Derive address from ratchet keys |

### Persistence

| Function | Description |
|----------|-------------|
| `listPeers(pubkey)` | List all known peers from DB |
| `hasPeerSession(pubkey, peerSignalId)` | Check if session exists |
| `deletePeer(pubkey, peerSignalId)` | Delete peer and associated state |
| `isEventProcessed(pubkey, eventId)` | Event deduplication check |
| `markEventProcessed(pubkey, eventId)` | Mark event as processed |

## Key Principles

- **Multi-Identity**: multiple Nostr identities coexist, each with isolated state and DB
- **Identity**: passed in from V1 (`nostrPrivkeyHex`), NOT generated
- **Wallet**: stamp token passed as string, wallet managed by V1
- **Storage**: All Signal sessions + MLS groups in SQLCipher DB, survives app restart
- **Multi-device**: `deviceId` parameter on init, `remoteDeviceId` on encrypt/decrypt
- **Persistence**: Signal sessions auto-persist via `SignalParticipant::persistent()`; MLS via `MlsProvider::open()`

## Build

```bash
cd rust && cargo build
```

## Test

```bash
cd rust && cargo test -- --test-threads=1
```

Test suites:
- `ffi_return_values` (16 tests) — FFI API structure and return types
- `persistence` (8 tests) — SQLCipher DB roundtrip, restart survival, encryption verification
- `three_party` (1 test) — Alice/Tom/Bob: 6 Signal sessions + MLS 3-member group
- `multi_identity` (4 tests) — multiple identities coexist, isolated, Signal session persistence

## Codegen

```bash
flutter_rust_bridge_codegen generate \
  --rust-input "crate::api_v2" \
  --rust-root rust/ \
  --dart-output lib/
```
