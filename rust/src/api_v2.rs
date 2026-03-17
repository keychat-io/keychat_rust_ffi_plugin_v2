use anyhow::Result;
use std::collections::HashMap;
use std::sync::Mutex;
use tokio::runtime::Runtime;

use libkeychat::{
    accept_friend_request, attach_ecash_stamp, create_gift_wrap, derive_nostr_address_from_ratchet,
    fetch_relay_info, receive_friend_request, send_friend_request, unwrap_gift_wrap,
    AddressManager, DeviceId, Event, Identity, KCMessage, Keys, MlsParticipant, ProtocolAddress,
    PublicKey, SecretKey, SignalParticipant,
};
/// Serialize a nostr 0.37 Event to JSON string.
fn event_to_json(event: &Event) -> String {
    serde_json::to_string(event).unwrap_or_default()
}

/// Deserialize a nostr 0.37 Event from JSON string.
fn event_from_json(json: &str) -> Result<Event> {
    serde_json::from_str(json).map_err(|e| anyhow!("invalid event JSON: {}", e))
}

// ─── Result types (flutter_rust_bridge generates Dart classes) ───────────────

#[derive(Debug, Clone)]
pub struct V2FriendRequestResult {
    pub event_json: String,
    pub first_inbox_pubkey: String,
    pub first_inbox_secret: String,
    pub signal_identity_hex: String,
}

#[derive(Debug, Clone)]
pub struct V2IncomingFriendRequest {
    pub sender_npub: String,
    pub sender_name: String,
    pub signal_identity_key: String,
    pub first_inbox: String,
    pub device_id: String,
    pub signal_signed_prekey_id: u32,
    pub signal_signed_prekey: String,
    pub signal_signed_prekey_signature: String,
    pub signal_one_time_prekey_id: u32,
    pub signal_one_time_prekey: String,
    pub signal_kyber_prekey_id: u32,
    pub signal_kyber_prekey: String,
    pub signal_kyber_prekey_signature: String,
    pub global_sign: String,
    pub payload_json: String,
}

#[derive(Debug, Clone)]
pub struct V2AcceptResult {
    pub event_json: String,
    pub peer_signal_identity: String,
}

#[derive(Debug, Clone)]
pub struct V2EncryptResult {
    pub ciphertext_base64: String,
    pub sender_address: String,
    pub new_receiving_addresses: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct V2DecryptResult {
    pub plaintext: String,
    pub sender_address: String,
    pub new_receiving_addresses: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct V2UnwrappedEvent {
    pub sender_npub: String,
    pub content: String,
    pub timestamp: u64,
}

#[derive(Debug, Clone)]
pub struct V2ParsedMessage {
    pub kind: String,
    pub content_json: String,
}

// ─── V2 State ───────────────────────────────────────────────────────────────

struct V2State {
    identity: Identity,
    /// peer signal_id -> SignalParticipant
    peers: HashMap<String, SignalParticipant>,
    /// peer signal_id -> AddressManager
    address_managers: HashMap<String, AddressManager>,
    /// Pending outbound friend requests: request_id -> (SignalParticipant, first_inbox_secret)
    pending_frs: HashMap<String, PendingFriendRequest>,
    /// MLS participant (lazy-init on first MLS call)
    mls: Option<MlsParticipant>,
    rt: Runtime,
}

struct PendingFriendRequest {
    signal: SignalParticipant,
    first_inbox_secret: String,
}

lazy_static! {
    static ref V2: Mutex<Option<V2State>> = Mutex::new(None);
}

fn with_state<F, T>(f: F) -> Result<T>
where
    F: FnOnce(&mut V2State) -> Result<T>,
{
    let mut guard = V2.lock().map_err(|e| anyhow!("V2 lock poisoned: {}", e))?;
    let state = guard
        .as_mut()
        .ok_or_else(|| anyhow!("V2 not initialized. Call init_v2() first."))?;
    f(state)
}

/// Create an Identity from a raw hex private key.
///
/// Safety: Identity is a newtype wrapper `struct Identity { keys: Keys }` with
/// no additional fields. Keys and Identity have identical memory layout, so
/// transmute is safe here. This avoids requiring the mnemonic (which V1 may
/// not have available) while still being able to call libkeychat functions
/// that take `&Identity`.
fn identity_from_secret_hex(secret_hex: &str) -> Result<Identity> {
    let sk = SecretKey::from_hex(secret_hex)
        .map_err(|e| anyhow!("invalid nostr private key hex: {}", e))?;
    let keys = Keys::new(sk);
    // Safety: Identity is repr(Rust) with a single field `keys: Keys`.
    // Both types have identical size and alignment.
    let identity: Identity = unsafe { std::mem::transmute(keys) };
    Ok(identity)
}

// ─── Initialization ─────────────────────────────────────────────────────────

pub fn init_v2(nostr_privkey_hex: String) -> Result<()> {
    let identity = identity_from_secret_hex(&nostr_privkey_hex)?;
    let rt = Runtime::new().map_err(|e| anyhow!("failed to create tokio runtime: {}", e))?;

    let mut guard = V2.lock().map_err(|e| anyhow!("V2 lock poisoned: {}", e))?;
    *guard = Some(V2State {
        identity,
        peers: HashMap::new(),
        address_managers: HashMap::new(),
        pending_frs: HashMap::new(),
        mls: None,
        rt,
    });
    Ok(())
}

// ─── Friend Request (PQXDH) ────────────────────────────────────────────────

pub fn v2_create_friend_request(
    peer_npub: String,
    display_name: String,
) -> Result<V2FriendRequestResult> {
    with_state(|state| {
        let peer_hex = libkeychat::normalize_pubkey(&peer_npub)
            .map_err(|e| anyhow!("invalid peer npub: {}", e))?;

        let (event, fr_state) = state.rt.block_on(send_friend_request(
            &state.identity,
            &peer_hex,
            &display_name,
            "flutter",
        ))?;

        let first_inbox_pubkey = fr_state.first_inbox_keys.pubkey_hex();
        let first_inbox_secret = fr_state.first_inbox_keys.secret_key().to_secret_hex();
        let signal_identity_hex = fr_state.signal_participant.identity_public_key_hex();
        let request_id = fr_state.request_id.clone();

        state.pending_frs.insert(
            request_id,
            PendingFriendRequest {
                signal: fr_state.signal_participant,
                first_inbox_secret: first_inbox_secret.clone(),
            },
        );

        Ok(V2FriendRequestResult {
            event_json: event_to_json(&event),
            first_inbox_pubkey,
            first_inbox_secret,
            signal_identity_hex,
        })
    })
}

pub fn v2_receive_friend_request(event_json: String) -> Result<V2IncomingFriendRequest> {
    with_state(|state| {
        let event = event_from_json(&event_json)?;
        let fr = receive_friend_request(&state.identity, &event)?;

        let payload = &fr.payload;
        let payload_json = serde_json::to_string(payload)?;

        Ok(V2IncomingFriendRequest {
            sender_npub: fr.sender_pubkey_hex.clone(),
            sender_name: payload.name.clone(),
            signal_identity_key: payload.signal_identity_key.clone(),
            first_inbox: payload.first_inbox.clone(),
            device_id: payload.device_id.clone(),
            signal_signed_prekey_id: payload.signal_signed_prekey_id,
            signal_signed_prekey: payload.signal_signed_prekey.clone(),
            signal_signed_prekey_signature: payload.signal_signed_prekey_signature.clone(),
            signal_one_time_prekey_id: payload.signal_one_time_prekey_id,
            signal_one_time_prekey: payload.signal_one_time_prekey.clone(),
            signal_kyber_prekey_id: payload.signal_kyber_prekey_id,
            signal_kyber_prekey: payload.signal_kyber_prekey.clone(),
            signal_kyber_prekey_signature: payload.signal_kyber_prekey_signature.clone(),
            global_sign: payload.global_sign.clone(),
            payload_json,
        })
    })
}

pub fn v2_accept_friend_request(
    event_json: String,
    my_display_name: String,
) -> Result<V2AcceptResult> {
    with_state(|state| {
        let event = event_from_json(&event_json)?;
        let fr = receive_friend_request(&state.identity, &event)?;

        let peer_signal_identity = fr.payload.signal_identity_key.clone();
        let peer_first_inbox = fr.payload.first_inbox.clone();
        let peer_nostr_hex = fr.sender_pubkey_hex.clone();

        let accepted = state.rt.block_on(accept_friend_request(
            &state.identity,
            &fr,
            &my_display_name,
        ))?;

        let signal_id = peer_signal_identity.clone();

        // Register peer
        let mut addr_mgr = AddressManager::new();
        addr_mgr.add_peer(&signal_id, Some(peer_first_inbox), Some(peer_nostr_hex));

        state.peers.insert(signal_id.clone(), accepted.signal_participant);
        state.address_managers.insert(signal_id, addr_mgr);

        Ok(V2AcceptResult {
            event_json: event_to_json(&accepted.event),
            peer_signal_identity,
        })
    })
}

// ─── Encrypt/Decrypt ────────────────────────────────────────────────────────

pub fn v2_encrypt(peer_signal_id: String, plaintext: String) -> Result<V2EncryptResult> {
    with_state(|state| {
        let signal = state
            .peers
            .get_mut(&peer_signal_id)
            .ok_or_else(|| anyhow!("unknown peer signal_id: {}", peer_signal_id))?;

        let remote_addr = ProtocolAddress::new(
            peer_signal_id.clone(),
            DeviceId::new(1).unwrap(),
        );

        let ct = signal.encrypt(&remote_addr, plaintext.as_bytes())?;

        let ciphertext_base64 = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            &ct.bytes,
        );

        let sender_address = ct.sender_address.clone().unwrap_or_default();

        // Update address manager
        let new_receiving = if let Some(addr_mgr) = state.address_managers.get_mut(&peer_signal_id)
        {
            let update = addr_mgr.on_encrypt(&peer_signal_id, ct.sender_address.as_deref())?;
            update.new_receiving
        } else {
            Vec::new()
        };

        Ok(V2EncryptResult {
            ciphertext_base64,
            sender_address,
            new_receiving_addresses: new_receiving,
        })
    })
}

pub fn v2_decrypt(
    peer_signal_id: String,
    ciphertext_base64: String,
) -> Result<V2DecryptResult> {
    with_state(|state| {
        let signal = state
            .peers
            .get_mut(&peer_signal_id)
            .ok_or_else(|| anyhow!("unknown peer signal_id: {}", peer_signal_id))?;

        let ciphertext = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &ciphertext_base64,
        )
        .map_err(|e| anyhow!("invalid base64 ciphertext: {}", e))?;

        let remote_addr = ProtocolAddress::new(
            peer_signal_id.clone(),
            DeviceId::new(1).unwrap(),
        );

        let result = signal.decrypt(&remote_addr, &ciphertext)?;

        let plaintext = String::from_utf8(result.plaintext)
            .map_err(|e| anyhow!("decrypted data is not valid UTF-8: {}", e))?;

        let sender_address = result.bob_derived_address.clone().unwrap_or_default();

        // Update address manager
        let new_receiving = if let Some(addr_mgr) = state.address_managers.get_mut(&peer_signal_id)
        {
            let update = addr_mgr.on_decrypt(
                &peer_signal_id,
                result.bob_derived_address.as_deref(),
                result.alice_addrs.as_deref(),
            )?;
            update.new_receiving
        } else {
            Vec::new()
        };

        Ok(V2DecryptResult {
            plaintext,
            sender_address,
            new_receiving_addresses: new_receiving,
        })
    })
}

// ─── Gift Wrap (kind:1059) ──────────────────────────────────────────────────

pub fn v2_wrap_event(inner_content: String, receiver_npub: String) -> Result<String> {
    with_state(|state| {
        let receiver_hex = libkeychat::normalize_pubkey(&receiver_npub)
            .map_err(|e| anyhow!("invalid receiver npub: {}", e))?;
        let receiver_pubkey = PublicKey::from_hex(&receiver_hex)
            .map_err(|e| anyhow!("invalid receiver pubkey: {}", e))?;

        let event = state.rt.block_on(create_gift_wrap(
            state.identity.keys(),
            &receiver_pubkey,
            &inner_content,
        ))?;

        Ok(event_to_json(&event))
    })
}

pub fn v2_unwrap_event(event_json: String) -> Result<V2UnwrappedEvent> {
    with_state(|state| {
        let event = event_from_json(&event_json)?;

        let unwrapped = unwrap_gift_wrap(state.identity.keys(), &event)?;

        Ok(V2UnwrappedEvent {
            sender_npub: unwrapped.sender_pubkey.to_hex(),
            content: unwrapped.content,
            timestamp: unwrapped.created_at.as_u64(),
        })
    })
}

// ─── Stamp ──────────────────────────────────────────────────────────────────

pub fn v2_fetch_relay_fees(relay_url: String) -> Result<String> {
    with_state(|state| {
        let info = state.rt.block_on(fetch_relay_info(&relay_url))?;
        let json = serde_json::to_string(&info)?;
        Ok(json)
    })
}

pub fn v2_stamp_event(event_json: String, cashu_token: String) -> Result<String> {
    let event = event_from_json(&event_json)?;
    let stamped = attach_ecash_stamp(&event, &cashu_token);
    Ok(stamped)
}

// ─── Address Management ─────────────────────────────────────────────────────

pub fn v2_derive_receiving_address(
    private_key_hex: String,
    public_key_hex: String,
) -> Result<String> {
    let seed_key = format!("{}-{}", private_key_hex, public_key_hex);
    let address = derive_nostr_address_from_ratchet(&seed_key)?;
    Ok(address)
}

pub fn v2_get_all_receiving_addresses(peer_signal_id: String) -> Result<Vec<String>> {
    with_state(|state| {
        let addr_mgr = state
            .address_managers
            .get(&peer_signal_id)
            .ok_or_else(|| anyhow!("no address manager for peer: {}", peer_signal_id))?;
        Ok(addr_mgr.get_all_receiving_address_strings())
    })
}

// ─── KCMessage V2 ───────────────────────────────────────────────────────────

pub fn v2_build_text_message(text: String) -> Result<String> {
    let msg = KCMessage::text(text);
    let json = msg.to_json().map_err(|e| anyhow!("failed to serialize KCMessage: {}", e))?;
    Ok(json)
}

pub fn v2_build_friend_request_message(payload_json: String) -> Result<String> {
    let payload = serde_json::from_str(&payload_json)
        .map_err(|e| anyhow!("invalid friend request payload JSON: {}", e))?;
    let id = format!("{:032x}", rand::random::<u128>());
    let msg = KCMessage::friend_request(id, payload);
    let json = msg.to_json().map_err(|e| anyhow!("failed to serialize KCMessage: {}", e))?;
    Ok(json)
}

pub fn v2_parse_message(json: String) -> Result<V2ParsedMessage> {
    let msg = KCMessage::try_parse(&json)
        .ok_or_else(|| anyhow!("failed to parse KCMessage v2 from JSON"))?;
    let kind = msg.kind.as_str().to_string();
    let content_json = serde_json::to_string(&serde_json::json!({
        "text": msg.text,
        "files": msg.files,
        "cashu": msg.cashu,
        "lightning": msg.lightning,
        "friend_request": msg.friend_request,
        "friend_approve": msg.friend_approve,
        "friend_reject": msg.friend_reject,
        "group_id": msg.group_id,
        "reply_to": msg.reply_to,
        "signal_prekey_auth": msg.signal_prekey_auth,
        "id": msg.id,
    }))?;

    Ok(V2ParsedMessage {
        kind,
        content_json,
    })
}

// ─── Peer management helpers ────────────────────────────────────────────────

pub fn v2_register_peer(
    peer_signal_id: String,
    peer_nostr_pubkey: String,
    first_inbox: Option<String>,
) -> Result<()> {
    with_state(|state| {
        if !state.address_managers.contains_key(&peer_signal_id) {
            let mut addr_mgr = AddressManager::new();
            addr_mgr.add_peer(&peer_signal_id, first_inbox, Some(peer_nostr_pubkey));
            state.address_managers.insert(peer_signal_id, addr_mgr);
        }
        Ok(())
    })
}

pub fn v2_resolve_send_address(peer_signal_id: String) -> Result<String> {
    with_state(|state| {
        let addr_mgr = state
            .address_managers
            .get(&peer_signal_id)
            .ok_or_else(|| anyhow!("no address manager for peer: {}", peer_signal_id))?;
        let addr = addr_mgr.resolve_send_address(&peer_signal_id)?;
        Ok(addr)
    })
}

// ─── MLS Group Operations ───────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct V2MlsAddMembersResult {
    pub commit_base64: String,
    pub welcome_base64: String,
}

#[derive(Debug, Clone)]
pub struct V2MlsDecryptResult {
    pub plaintext: String,
    pub sender_id: String,
}

#[derive(Debug, Clone)]
pub struct V2MlsGroupInfo {
    pub name: String,
    pub status: String,
    pub admins_json: String,
}

/// Helper: get or create MlsParticipant
fn get_mls(state: &mut V2State) -> Result<&MlsParticipant> {
    if state.mls.is_none() {
        let npub_hex = state.identity.keys().public_key().to_string();
        state.mls = Some(MlsParticipant::new(npub_hex));
    }
    Ok(state.mls.as_ref().unwrap())
}

/// Initialize MLS subsystem. Creates MlsParticipant from identity npub.
pub fn v2_mls_init() -> Result<()> {
    with_state(|state| {
        get_mls(state)?;
        Ok(())
    })
}

/// Generate a KeyPackage (base64-encoded).
pub fn v2_mls_generate_key_package() -> Result<String> {
    use base64::Engine;
    with_state(|state| {
        let mls = get_mls(state)?;
        let kp = mls.generate_key_package()?;
        // KeyPackage → bytes via serde (openmls supports it)
        let kp_bytes = serde_json::to_vec(&kp)?;
        Ok(base64::engine::general_purpose::STANDARD.encode(&kp_bytes))
    })
}

/// Create a new MLS group.
pub fn v2_mls_create_group(group_id: String, name: String) -> Result<()> {
    with_state(|state| {
        let mls = get_mls(state)?;
        mls.create_group(&group_id, &name)?;
        Ok(())
    })
}

/// Add members. key_packages_base64_json: JSON array of base64 KeyPackage bytes.
pub fn v2_mls_add_members(
    group_id: String,
    key_packages_base64_json: String,
) -> Result<V2MlsAddMembersResult> {
    use base64::Engine;
    with_state(|state| {
        let mls = get_mls(state)?;
        let kp_b64_list: Vec<String> = serde_json::from_str(&key_packages_base64_json)?;
        let key_packages: Vec<_> = kp_b64_list
            .iter()
            .map(|b64| {
                let bytes = base64::engine::general_purpose::STANDARD.decode(b64)?;
                let kp = serde_json::from_slice(&bytes)?;
                Ok(kp)
            })
            .collect::<Result<Vec<_>>>()?;

        let (commit_bytes, welcome_bytes) = mls.add_members(&group_id, key_packages)?;
        Ok(V2MlsAddMembersResult {
            commit_base64: base64::engine::general_purpose::STANDARD.encode(&commit_bytes),
            welcome_base64: base64::engine::general_purpose::STANDARD.encode(&welcome_bytes),
        })
    })
}

/// Join a group via Welcome (base64). Returns group_id.
pub fn v2_mls_join_group(welcome_base64: String) -> Result<String> {
    use base64::Engine;
    with_state(|state| {
        let mls = get_mls(state)?;
        let bytes = base64::engine::general_purpose::STANDARD.decode(&welcome_base64)?;
        Ok(mls.join_group(&bytes)?)
    })
}

/// Encrypt plaintext for MLS group. Returns ciphertext base64.
pub fn v2_mls_encrypt(group_id: String, plaintext: String) -> Result<String> {
    use base64::Engine;
    with_state(|state| {
        let mls = get_mls(state)?;
        let ct = mls.encrypt(&group_id, plaintext.as_bytes())?;
        Ok(base64::engine::general_purpose::STANDARD.encode(&ct))
    })
}

/// Decrypt MLS ciphertext (base64). Returns plaintext + sender_id.
pub fn v2_mls_decrypt(group_id: String, ciphertext_base64: String) -> Result<V2MlsDecryptResult> {
    use base64::Engine;
    with_state(|state| {
        let mls = get_mls(state)?;
        let ct = base64::engine::general_purpose::STANDARD.decode(&ciphertext_base64)?;
        let (pt_bytes, sender_id) = mls.decrypt(&group_id, &ct)?;
        Ok(V2MlsDecryptResult {
            plaintext: String::from_utf8(pt_bytes)?,
            sender_id,
        })
    })
}

/// Remove members by nostr ID (JSON array). Returns commit base64.
pub fn v2_mls_remove_members(group_id: String, member_ids_json: String) -> Result<String> {
    use base64::Engine;
    with_state(|state| {
        let mls = get_mls(state)?;
        let member_ids: Vec<String> = serde_json::from_str(&member_ids_json)?;
        let indices: Vec<_> = member_ids
            .iter()
            .map(|id| mls.find_member_index(&group_id, id).map_err(|e| anyhow!("{}", e)))
            .collect::<Result<Vec<_>>>()?;
        let commit = mls.remove_members(&group_id, &indices)?;
        Ok(base64::engine::general_purpose::STANDARD.encode(&commit))
    })
}

/// Self-update (key rotation). Returns commit base64.
pub fn v2_mls_self_update(group_id: String) -> Result<String> {
    use base64::Engine;
    with_state(|state| {
        let mls = get_mls(state)?;
        let commit = mls.self_update(&group_id)?;
        Ok(base64::engine::general_purpose::STANDARD.encode(&commit))
    })
}

/// Leave a group. Returns proposal base64.
pub fn v2_mls_leave_group(group_id: String) -> Result<String> {
    use base64::Engine;
    with_state(|state| {
        let mls = get_mls(state)?;
        let proposal = mls.leave_group(&group_id)?;
        Ok(base64::engine::general_purpose::STANDARD.encode(&proposal))
    })
}

/// Process incoming MLS Commit (base64).
pub fn v2_mls_process_commit(group_id: String, commit_base64: String) -> Result<()> {
    use base64::Engine;
    with_state(|state| {
        let mls = get_mls(state)?;
        let bytes = base64::engine::general_purpose::STANDARD.decode(&commit_base64)?;
        mls.process_commit(&group_id, &bytes)?;
        Ok(())
    })
}

/// Derive shared MLS temp inbox address.
pub fn v2_mls_derive_temp_inbox(group_id: String) -> Result<String> {
    with_state(|state| {
        let mls = get_mls(state)?;
        Ok(mls.derive_temp_inbox(&group_id)?)
    })
}

/// List group members (nostr IDs).
pub fn v2_mls_group_members(group_id: String) -> Result<Vec<String>> {
    with_state(|state| {
        let mls = get_mls(state)?;
        Ok(mls.group_members(&group_id)?)
    })
}

/// Update group context. Returns commit base64.
pub fn v2_mls_update_group(
    group_id: String,
    name: Option<String>,
    status: Option<String>,
    admin_pubkeys_json: Option<String>,
) -> Result<String> {
    use base64::Engine;
    with_state(|state| {
        let mls = get_mls(state)?;
        let admin_pubkeys: Option<Vec<String>> = admin_pubkeys_json
            .as_ref()
            .map(|json| serde_json::from_str(json))
            .transpose()?;

        let commit = mls.update_group_context_extensions(
            &group_id,
            name.as_deref(),
            status.as_deref(),
            admin_pubkeys,
        )?;
        Ok(base64::engine::general_purpose::STANDARD.encode(&commit))
    })
}

/// Get group info.
pub fn v2_mls_group_info(group_id: String) -> Result<V2MlsGroupInfo> {
    with_state(|state| {
        let mls = get_mls(state)?;
        let ext = mls.group_extension(&group_id)?;
        Ok(V2MlsGroupInfo {
            name: String::from_utf8_lossy(&ext.name).to_string(),
            status: String::from_utf8_lossy(&ext.status).to_string(),
            admins_json: serde_json::to_string(&ext.admin_pubkeys.iter().map(|k| hex::encode(k)).collect::<Vec<_>>())?,
        })
    })
}

