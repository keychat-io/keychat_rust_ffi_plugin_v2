# keychat_rust_ffi_plugin_v2

Flutter FFI plugin for Keychat Protocol V2.

Wraps [libkeychat](https://github.com/keychat-io/keychat-protocol) as a pure crypto engine — identity and wallet are managed by V1.

## Architecture

```
keychat_rust_ffi_plugin      (V1: Signal X3DH, MLS kc4, CDK kc2)
keychat_rust_ffi_plugin_v2   (V2: Signal PQXDH via libkeychat)
```

Two independent Rust projects, two independent dependency trees, zero conflicts.

## V2 API

| Function | Description |
|----------|-------------|
| `initV2(nostrPrivkeyHex)` | Initialize from existing V1 private key |
| `v2CreateFriendRequest` | Send PQXDH friend request (kind:1059) |
| `v2ReceiveFriendRequest` | Parse incoming friend request |
| `v2AcceptFriendRequest` | Accept and establish V2 session |
| `v2Encrypt` / `v2Decrypt` | Signal PQXDH encrypt/decrypt |
| `v2WrapEvent` / `v2UnwrapEvent` | Kind:1059 Gift Wrap |
| `v2FetchRelayFees` | NIP-11 relay fee discovery |
| `v2StampEvent` | Attach ecash stamp (token from V1 wallet) |
| `v2BuildTextMessage` / `v2ParseMessage` | KCMessage v2 format |
| `v2RegisterPeer` / `v2ResolveSendAddress` | Peer + address management |

## Key Principle

- **Identity**: passed in from V1 (`nostrPrivkeyHex`), NOT generated
- **Wallet**: stamp token passed as string, wallet managed by V1
- **Storage**: V2 Signal sessions in separate SQLCipher DB (managed by libkeychat)
- **No MLS, no CDK** in this plugin — features disabled to avoid dep conflicts

## Build

```bash
cd rust && cargo build
```

## Codegen

```bash
flutter_rust_bridge_codegen generate \
  --rust-input "crate::api_v2" \
  --rust-root rust/ \
  --dart-output lib/
```
