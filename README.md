# keychat_rust_ffi_plugin_v2

Flutter FFI plugin for Keychat Protocol V2.

Wraps [libkeychat](https://github.com/keychat-io/keychat-protocol) — Signal PQXDH + MLS + SQLCipher persistent storage.

## Architecture

```
keychat_rust_ffi_plugin      (V1: Signal X3DH, MLS kc4, CDK kc2)
keychat_rust_ffi_plugin_v2   (V2: Signal PQXDH + MLS RFC9420 via libkeychat, SQLCipher storage)
```

Two independent Rust projects, two independent dependency trees, zero conflicts.

## V2 API

### Init

| Function | Description |
|----------|-------------|
| `initV2(nostrPrivkeyHex, dbPath, dbKey, deviceId)` | Initialize with SQLCipher DB + multi-device support |
| `getDeviceId()` | Get current device ID |

### Signal 1:1 Messaging

| Function | Description |
|----------|-------------|
| `createFriendRequest(peerNpub, displayName)` | Send PQXDH friend request (kind:1059) |
| `receiveFriendRequest(eventJson)` | Parse incoming friend request |
| `acceptFriendRequest(eventJson, displayName)` | Accept and establish Signal session |
| `encrypt(peerSignalId, plaintext, remoteDeviceId)` | Signal PQXDH encrypt |
| `decrypt(peerSignalId, ciphertextBase64, remoteDeviceId)` | Signal PQXDH decrypt |

### MLS Group Messaging (RFC 9420)

| Function | Description |
|----------|-------------|
| `mlsInit()` | Initialize MLS subsystem (file-backed storage) |
| `mlsCreateGroup(groupId, name)` | Create MLS group |
| `mlsAddMembers(groupId, keyPackagesJson)` | Add members, returns commit + welcome |
| `mlsJoinGroup(welcomeBase64)` | Join group via Welcome |
| `mlsEncrypt(groupId, plaintext)` / `mlsDecrypt(groupId, ciphertextBase64)` | Group encrypt/decrypt |
| `mlsGroupMembers(groupId)` | List group members |
| `mlsRemoveMembers` / `mlsSelfUpdate` / `mlsLeaveGroup` | Group management |
| `mlsProcessCommit` / `mlsUpdateGroup` / `mlsGroupInfo` | Commit processing + metadata |
| `mlsGenerateKeyPackage()` | Generate KeyPackage for group invitation |
| `mlsDeriveTempInbox(groupId)` | Derive shared temp inbox address |

### Gift Wrap & Stamp

| Function | Description |
|----------|-------------|
| `wrapEvent` / `unwrapEvent` | Kind:1059 Gift Wrap |
| `fetchRelayFees` | NIP-11 relay fee discovery |
| `stampEvent` | Attach ecash stamp |

### KCMessage V2

| Function | Description |
|----------|-------------|
| `buildTextMessage` / `parseMessage` | KCMessage v2 format |
| `buildFriendRequestMessage` | Build friend request payload |

### Peer & Address Management

| Function | Description |
|----------|-------------|
| `registerPeer` / `resolveSendAddress` | Peer + address management |
| `getAllReceivingAddresses` | Get all receiving addresses for a peer |
| `deriveReceivingAddress` | Derive address from ratchet keys |

### Persistence

| Function | Description |
|----------|-------------|
| `listPeers()` | List all known peers from DB |
| `hasPeerSession(peerSignalId)` | Check if session exists |
| `deletePeer(peerSignalId)` | Delete peer and associated state |
| `isEventProcessed(eventId)` | Event deduplication check |
| `markEventProcessed(eventId)` | Mark event as processed |

## Key Principles

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
cd rust && cargo test --test three_party --test persistence --test ffi_return_values -- --test-threads=1
```

## Codegen

```bash
flutter_rust_bridge_codegen generate \
  --rust-input "crate::api_v2" \
  --rust-root rust/ \
  --dart-output lib/
```
