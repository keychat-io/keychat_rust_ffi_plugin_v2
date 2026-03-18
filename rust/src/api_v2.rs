use anyhow::Result;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::runtime::Runtime;

use libkeychat::{
    accept_friend_request_persistent, attach_ecash_stamp, create_gift_wrap,
    derive_nostr_address_from_ratchet, fetch_relay_info, generate_prekey_material,
    receive_friend_request as lk_receive_friend_request, send_friend_request_persistent,
    unwrap_gift_wrap, AddressManager, DeviceId, Event, GenericSignedPreKey, Identity, IdentityKey,
    IdentityKeyPair, KCMessage, Keys, KyberPreKeyId, KyberPreKeyRecord, MlsParticipant,
    MlsProvider, PreKeyId, PreKeyRecord, ProtocolAddress, PublicKey, SecretKey, SecureStorage,
    SignalParticipant, SignalPreKeyMaterial, SignalPrivateKey, SignedPreKeyId, SignedPreKeyRecord,
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
    device_id: u32,
    storage: Arc<Mutex<SecureStorage>>,
    /// peer signal_id -> SignalParticipant (persistent, backed by SQLCipher)
    peers: HashMap<String, SignalParticipant>,
    /// peer signal_id -> AddressManager
    address_managers: HashMap<String, AddressManager>,
    /// Pending outbound friend requests: request_id -> (SignalParticipant, first_inbox_secret)
    pending_frs: HashMap<String, PendingFriendRequest>,
    /// MLS participant (lazy-init on first MLS call, file-backed)
    mls: Option<MlsParticipant>,
    mls_db_path: String,
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
fn identity_from_secret_hex(secret_hex: &str) -> Result<Identity> {
    let sk = SecretKey::from_hex(secret_hex)
        .map_err(|e| anyhow!("invalid nostr private key hex: {}", e))?;
    let keys = Keys::new(sk);
    // Safety: Identity is repr(Rust) with a single field `keys: Keys`.
    let identity: Identity = unsafe { std::mem::transmute(keys) };
    Ok(identity)
}

// ─── Key material helpers ───────────────────────────────────────────────────

/// Save SignalPreKeyMaterial to the signal_participants table.
fn save_keys_to_db(
    db: &SecureStorage,
    peer_signal_id: &str,
    device_id: u32,
    keys: &SignalPreKeyMaterial,
) -> Result<()> {
    let identity_public = keys.identity_key_pair.identity_key().serialize().to_vec();
    let identity_private = keys.identity_key_pair.private_key().serialize().to_vec();
    let signed_prekey_record = keys.signed_prekey.serialize()?;
    let prekey_record = keys.prekey.serialize()?;
    let kyber_prekey_record = keys.kyber_prekey.serialize()?;

    db.save_signal_participant(
        peer_signal_id,
        device_id,
        &identity_public,
        &identity_private,
        keys.registration_id,
        u32::from(keys.signed_prekey_id),
        &signed_prekey_record,
        u32::from(keys.prekey_id),
        &prekey_record,
        u32::from(keys.kyber_prekey_id),
        &kyber_prekey_record,
    )?;
    Ok(())
}

/// Save SignalPreKeyMaterial to the pending_friend_requests table.
fn save_pending_keys_to_db(
    db: &SecureStorage,
    request_id: &str,
    device_id: u32,
    keys: &SignalPreKeyMaterial,
    first_inbox_secret: &str,
) -> Result<()> {
    let identity_public = keys.identity_key_pair.identity_key().serialize().to_vec();
    let identity_private = keys.identity_key_pair.private_key().serialize().to_vec();
    let signed_prekey_record = keys.signed_prekey.serialize()?;
    let prekey_record = keys.prekey.serialize()?;
    let kyber_prekey_record = keys.kyber_prekey.serialize()?;

    db.save_pending_fr(
        request_id,
        device_id,
        &identity_public,
        &identity_private,
        keys.registration_id,
        u32::from(keys.signed_prekey_id),
        &signed_prekey_record,
        u32::from(keys.prekey_id),
        &prekey_record,
        u32::from(keys.kyber_prekey_id),
        &kyber_prekey_record,
        first_inbox_secret,
    )?;
    Ok(())
}

/// Reconstruct SignalPreKeyMaterial from raw DB columns.
fn reconstruct_keys(
    identity_public: &[u8],
    identity_private: &[u8],
    registration_id: u32,
    signed_prekey_id: u32,
    signed_prekey_record: &[u8],
    prekey_id: u32,
    prekey_record: &[u8],
    kyber_prekey_id: u32,
    kyber_prekey_record: &[u8],
) -> Result<SignalPreKeyMaterial> {
    let identity_key = IdentityKey::decode(identity_public)
        .map_err(|e| anyhow!("failed to decode identity public key: {}", e))?;
    let private_key = SignalPrivateKey::deserialize(identity_private)
        .map_err(|e| anyhow!("failed to decode identity private key: {}", e))?;
    let identity_key_pair = IdentityKeyPair::new(identity_key, private_key);

    let signed_prekey = SignedPreKeyRecord::deserialize(signed_prekey_record)
        .map_err(|e| anyhow!("failed to deserialize signed prekey: {}", e))?;
    let prekey = PreKeyRecord::deserialize(prekey_record)
        .map_err(|e| anyhow!("failed to deserialize prekey: {}", e))?;
    let kyber_prekey = KyberPreKeyRecord::deserialize(kyber_prekey_record)
        .map_err(|e| anyhow!("failed to deserialize kyber prekey: {}", e))?;

    Ok(SignalPreKeyMaterial {
        identity_key_pair,
        registration_id,
        signed_prekey_id: SignedPreKeyId::from(signed_prekey_id),
        signed_prekey,
        prekey_id: PreKeyId::from(prekey_id),
        prekey,
        kyber_prekey_id: KyberPreKeyId::from(kyber_prekey_id),
        kyber_prekey,
    })
}

/// Persist address state for a peer.
fn persist_address_state(
    storage: &Arc<Mutex<SecureStorage>>,
    peer_signal_id: &str,
    addr_mgr: &AddressManager,
) -> Result<()> {
    if let Some(state_ser) = addr_mgr.to_serialized(peer_signal_id) {
        let db = storage.lock().map_err(|e| anyhow!("lock: {}", e))?;
        db.save_peer_addresses(peer_signal_id, &state_ser)?;
    }
    Ok(())
}

// ─── Initialization ─────────────────────────────────────────────────────────

pub fn init_v2(
    nostr_privkey_hex: String,
    db_path: String,
    db_key: String,
    device_id: u32,
) -> Result<()> {
    let identity = identity_from_secret_hex(&nostr_privkey_hex)?;
    let storage = Arc::new(Mutex::new(
        SecureStorage::open(&db_path, &db_key)
            .map_err(|e| anyhow!("failed to open SQLCipher DB: {}", e))?,
    ));
    let rt = Runtime::new().map_err(|e| anyhow!("failed to create tokio runtime: {}", e))?;

    // Restore peers from DB
    let mut peers = HashMap::new();
    {
        let db = storage.lock().map_err(|e| anyhow!("lock: {}", e))?;
        for peer_id in db.list_signal_participants()? {
            if let Some((
                dev_id,
                id_pub,
                id_priv,
                reg_id,
                spk_id,
                spk_rec,
                pk_id,
                pk_rec,
                kpk_id,
                kpk_rec,
            )) = db.load_signal_participant(&peer_id)?
            {
                let keys = reconstruct_keys(
                    &id_pub, &id_priv, reg_id, spk_id, &spk_rec, pk_id, &pk_rec, kpk_id, &kpk_rec,
                )?;
                let participant = SignalParticipant::persistent(
                    identity.pubkey_hex(),
                    dev_id,
                    keys,
                    storage.clone(),
                )
                .map_err(|e| anyhow!("failed to restore participant {}: {}", peer_id, e))?;
                peers.insert(peer_id, participant);
            }
        }
    }

    // Restore address managers from DB
    let mut address_managers = HashMap::new();
    {
        let db = storage.lock().map_err(|e| anyhow!("lock: {}", e))?;
        for (peer_id, state) in db.load_all_peer_addresses()? {
            let mgr = AddressManager::from_serialized(&peer_id, state);
            address_managers.insert(peer_id, mgr);
        }
    }

    // Restore pending friend requests from DB
    let mut pending_frs = HashMap::new();
    {
        let db = storage.lock().map_err(|e| anyhow!("lock: {}", e))?;
        for request_id in db.list_pending_frs()? {
            if let Some((
                dev_id,
                id_pub,
                id_priv,
                reg_id,
                spk_id,
                spk_rec,
                pk_id,
                pk_rec,
                kpk_id,
                kpk_rec,
                secret,
            )) = db.load_pending_fr(&request_id)?
            {
                let keys = reconstruct_keys(
                    &id_pub, &id_priv, reg_id, spk_id, &spk_rec, pk_id, &pk_rec, kpk_id, &kpk_rec,
                )?;
                let signal = SignalParticipant::persistent(
                    identity.pubkey_hex(),
                    dev_id,
                    keys,
                    storage.clone(),
                )
                .map_err(|e| anyhow!("failed to restore pending FR {}: {}", request_id, e))?;
                pending_frs.insert(
                    request_id,
                    PendingFriendRequest {
                        signal,
                        first_inbox_secret: secret,
                    },
                );
            }
        }
    }

    let mls_db_path = db_path.replace(".db", "_mls.db");

    let mut guard = V2.lock().map_err(|e| anyhow!("V2 lock poisoned: {}", e))?;
    *guard = Some(V2State {
        identity,
        device_id,
        storage,
        peers,
        address_managers,
        pending_frs,
        mls: None,
        mls_db_path,
        rt,
    });
    Ok(())
}

// ─── Friend Request (PQXDH) ────────────────────────────────────────────────

pub fn create_friend_request(
    peer_npub: String,
    display_name: String,
) -> Result<V2FriendRequestResult> {
    with_state(|state| {
        let peer_hex = libkeychat::normalize_pubkey(&peer_npub)
            .map_err(|e| anyhow!("invalid peer npub: {}", e))?;

        // Generate keys and save to DB before creating participant
        let keys = generate_prekey_material()
            .map_err(|e| anyhow!("failed to generate prekey material: {}", e))?;

        let (event, fr_state) = state.rt.block_on(send_friend_request_persistent(
            &state.identity,
            &peer_hex,
            &display_name,
            &state.device_id.to_string(),
            keys.clone(),
            state.storage.clone(),
            state.device_id,
        ))?;

        let first_inbox_pubkey = fr_state.first_inbox_keys.pubkey_hex();
        let first_inbox_secret = fr_state.first_inbox_keys.secret_key().to_secret_hex();
        let signal_identity_hex = fr_state.signal_participant.identity_public_key_hex();
        let request_id = fr_state.request_id.clone();

        // Save pending FR to DB
        {
            let db = state.storage.lock().map_err(|e| anyhow!("lock: {}", e))?;
            save_pending_keys_to_db(&db, &request_id, state.device_id, &keys, &first_inbox_secret)?;
        }

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

pub fn receive_friend_request(event_json: String) -> Result<V2IncomingFriendRequest> {
    with_state(|state| {
        let event = event_from_json(&event_json)?;
        let fr = lk_receive_friend_request(&state.identity, &event)?;

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

pub fn accept_friend_request(
    event_json: String,
    my_display_name: String,
) -> Result<V2AcceptResult> {
    with_state(|state| {
        let event = event_from_json(&event_json)?;
        let fr = lk_receive_friend_request(&state.identity, &event)?;

        let peer_signal_identity = fr.payload.signal_identity_key.clone();
        let peer_first_inbox = fr.payload.first_inbox.clone();
        let peer_nostr_hex = fr.sender_pubkey_hex.clone();

        // Generate keys and save to DB before creating participant
        let keys = generate_prekey_material()
            .map_err(|e| anyhow!("failed to generate prekey material: {}", e))?;

        let accepted = state.rt.block_on(accept_friend_request_persistent(
            &state.identity,
            &fr,
            &my_display_name,
            keys.clone(),
            state.storage.clone(),
            state.device_id,
        ))?;

        let signal_id = peer_signal_identity.clone();

        // Save participant key material + peer mapping + address state
        {
            let db = state.storage.lock().map_err(|e| anyhow!("lock: {}", e))?;
            save_keys_to_db(&db, &signal_id, state.device_id, &keys)?;
            db.save_peer_mapping(&peer_nostr_hex, &signal_id, &my_display_name)?;
        }

        // Register peer address manager
        let mut addr_mgr = AddressManager::new();
        addr_mgr.add_peer(
            &signal_id,
            Some(peer_first_inbox),
            Some(peer_nostr_hex),
        );
        persist_address_state(&state.storage, &signal_id, &addr_mgr)?;

        state
            .peers
            .insert(signal_id.clone(), accepted.signal_participant);
        state.address_managers.insert(signal_id, addr_mgr);

        Ok(V2AcceptResult {
            event_json: event_to_json(&accepted.event),
            peer_signal_identity,
        })
    })
}

// ─── Encrypt/Decrypt ────────────────────────────────────────────────────────

pub fn encrypt(
    peer_signal_id: String,
    plaintext: String,
    remote_device_id: u32,
) -> Result<V2EncryptResult> {
    with_state(|state| {
        let signal = state
            .peers
            .get_mut(&peer_signal_id)
            .ok_or_else(|| anyhow!("unknown peer signal_id: {}", peer_signal_id))?;

        let remote_addr = ProtocolAddress::new(
            peer_signal_id.clone(),
            DeviceId::new(remote_device_id as u8).unwrap(),
        );

        // encrypt → persistent store auto-saves session to SQLCipher
        let ct = signal.encrypt(&remote_addr, plaintext.as_bytes())?;

        let ciphertext_base64 = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            &ct.bytes,
        );

        let sender_address = ct.sender_address.clone().unwrap_or_default();

        // Update address manager + persist
        let new_receiving =
            if let Some(addr_mgr) = state.address_managers.get_mut(&peer_signal_id) {
                let update =
                    addr_mgr.on_encrypt(&peer_signal_id, ct.sender_address.as_deref())?;
                persist_address_state(&state.storage, &peer_signal_id, addr_mgr)?;
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

pub fn decrypt(
    peer_signal_id: String,
    ciphertext_base64: String,
    remote_device_id: u32,
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
            DeviceId::new(remote_device_id as u8).unwrap(),
        );

        // decrypt → persistent store auto-saves session to SQLCipher
        let result = signal.decrypt(&remote_addr, &ciphertext)?;

        let plaintext = String::from_utf8(result.plaintext)
            .map_err(|e| anyhow!("decrypted data is not valid UTF-8: {}", e))?;

        let sender_address = result.bob_derived_address.clone().unwrap_or_default();

        // Update address manager + persist
        let new_receiving =
            if let Some(addr_mgr) = state.address_managers.get_mut(&peer_signal_id) {
                let update = addr_mgr.on_decrypt(
                    &peer_signal_id,
                    result.bob_derived_address.as_deref(),
                    result.alice_addrs.as_deref(),
                )?;
                persist_address_state(&state.storage, &peer_signal_id, addr_mgr)?;
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

pub fn wrap_event(inner_content: String, receiver_npub: String) -> Result<String> {
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

pub fn unwrap_event(event_json: String) -> Result<V2UnwrappedEvent> {
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

pub fn fetch_relay_fees(relay_url: String) -> Result<String> {
    with_state(|state| {
        let info = state.rt.block_on(fetch_relay_info(&relay_url))?;
        let json = serde_json::to_string(&info)?;
        Ok(json)
    })
}

pub fn stamp_event(event_json: String, cashu_token: String) -> Result<String> {
    let event = event_from_json(&event_json)?;
    let stamped = attach_ecash_stamp(&event, &cashu_token);
    Ok(stamped)
}

// ─── Address Management ─────────────────────────────────────────────────────

pub fn derive_receiving_address(
    private_key_hex: String,
    public_key_hex: String,
) -> Result<String> {
    let seed_key = format!("{}-{}", private_key_hex, public_key_hex);
    let address = derive_nostr_address_from_ratchet(&seed_key)?;
    Ok(address)
}

pub fn get_all_receiving_addresses(peer_signal_id: String) -> Result<Vec<String>> {
    with_state(|state| {
        let addr_mgr = state
            .address_managers
            .get(&peer_signal_id)
            .ok_or_else(|| anyhow!("no address manager for peer: {}", peer_signal_id))?;
        Ok(addr_mgr.get_all_receiving_address_strings())
    })
}

// ─── KCMessage V2 ───────────────────────────────────────────────────────────

pub fn build_text_message(text: String) -> Result<String> {
    let msg = KCMessage::text(text);
    let json = msg
        .to_json()
        .map_err(|e| anyhow!("failed to serialize KCMessage: {}", e))?;
    Ok(json)
}

pub fn build_friend_request_message(payload_json: String) -> Result<String> {
    let payload = serde_json::from_str(&payload_json)
        .map_err(|e| anyhow!("invalid friend request payload JSON: {}", e))?;
    let id = format!("{:032x}", rand::random::<u128>());
    let msg = KCMessage::friend_request(id, payload);
    let json = msg
        .to_json()
        .map_err(|e| anyhow!("failed to serialize KCMessage: {}", e))?;
    Ok(json)
}

pub fn parse_message(json: String) -> Result<V2ParsedMessage> {
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

pub fn register_peer(
    peer_signal_id: String,
    peer_nostr_pubkey: String,
    first_inbox: Option<String>,
) -> Result<()> {
    with_state(|state| {
        if !state.address_managers.contains_key(&peer_signal_id) {
            let mut addr_mgr = AddressManager::new();
            addr_mgr.add_peer(&peer_signal_id, first_inbox, Some(peer_nostr_pubkey));
            persist_address_state(&state.storage, &peer_signal_id, &addr_mgr)?;
            state.address_managers.insert(peer_signal_id, addr_mgr);
        }
        Ok(())
    })
}

pub fn resolve_send_address(peer_signal_id: String) -> Result<String> {
    with_state(|state| {
        let addr_mgr = state
            .address_managers
            .get(&peer_signal_id)
            .ok_or_else(|| anyhow!("no address manager for peer: {}", peer_signal_id))?;
        let addr = addr_mgr.resolve_send_address(&peer_signal_id)?;
        Ok(addr)
    })
}

// ─── Persistence-specific APIs ──────────────────────────────────────────────

/// List all known peers from DB.
pub fn list_peers() -> Result<Vec<String>> {
    with_state(|state| {
        let db = state.storage.lock().map_err(|e| anyhow!("lock: {}", e))?;
        let peers = db.list_peers()?;
        Ok(peers
            .iter()
            .map(|p| {
                serde_json::to_string(&serde_json::json!({
                    "nostr_pubkey": p.nostr_pubkey,
                    "signal_id": p.signal_id,
                    "name": p.name,
                    "created_at": p.created_at,
                }))
                .unwrap_or_default()
            })
            .collect())
    })
}

/// Check if we have a session with a peer.
pub fn has_peer_session(peer_signal_id: String) -> Result<bool> {
    with_state(|state| Ok(state.peers.contains_key(&peer_signal_id)))
}

/// Delete a peer and all associated state.
pub fn delete_peer(peer_signal_id: String) -> Result<()> {
    with_state(|state| {
        state.peers.remove(&peer_signal_id);
        state.address_managers.remove(&peer_signal_id);

        let db = state.storage.lock().map_err(|e| anyhow!("lock: {}", e))?;
        db.delete_signal_participant(&peer_signal_id)?;
        db.delete_peer_addresses(&peer_signal_id)?;
        Ok(())
    })
}

/// Check if an event was already processed (deduplication).
pub fn is_event_processed(event_id: String) -> Result<bool> {
    with_state(|state| {
        let db = state.storage.lock().map_err(|e| anyhow!("lock: {}", e))?;
        Ok(db.is_event_processed(&event_id)?)
    })
}

/// Mark an event as processed.
pub fn mark_event_processed(event_id: String) -> Result<()> {
    with_state(|state| {
        let db = state.storage.lock().map_err(|e| anyhow!("lock: {}", e))?;
        db.mark_event_processed(&event_id)?;
        Ok(())
    })
}

/// Get the current device ID.
pub fn get_device_id() -> Result<u32> {
    with_state(|state| Ok(state.device_id))
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

/// Helper: get or create MlsParticipant with file-backed storage.
fn get_mls(state: &mut V2State) -> Result<&MlsParticipant> {
    if state.mls.is_none() {
        let npub_hex = state.identity.keys().public_key().to_string();
        let provider = MlsProvider::open(&state.mls_db_path)
            .map_err(|e| anyhow!("failed to open MLS storage: {}", e))?;
        state.mls = Some(MlsParticipant::with_provider(npub_hex, provider));
    }
    Ok(state.mls.as_ref().unwrap())
}

/// Initialize MLS subsystem.
pub fn mls_init() -> Result<()> {
    with_state(|state| {
        get_mls(state)?;
        Ok(())
    })
}

/// Generate a KeyPackage (base64-encoded).
pub fn mls_generate_key_package() -> Result<String> {
    use base64::Engine;
    with_state(|state| {
        let mls = get_mls(state)?;
        let kp = mls.generate_key_package()?;
        let kp_bytes = serde_json::to_vec(&kp)?;
        Ok(base64::engine::general_purpose::STANDARD.encode(&kp_bytes))
    })
}

/// Create a new MLS group.
pub fn mls_create_group(group_id: String, name: String) -> Result<()> {
    with_state(|state| {
        let mls = get_mls(state)?;
        mls.create_group(&group_id, &name)?;
        Ok(())
    })
}

/// Add members. key_packages_base64_json: JSON array of base64 KeyPackage bytes.
pub fn mls_add_members(
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
pub fn mls_join_group(welcome_base64: String) -> Result<String> {
    use base64::Engine;
    with_state(|state| {
        let mls = get_mls(state)?;
        let bytes = base64::engine::general_purpose::STANDARD.decode(&welcome_base64)?;
        Ok(mls.join_group(&bytes)?)
    })
}

/// Encrypt plaintext for MLS group. Returns ciphertext base64.
pub fn mls_encrypt(group_id: String, plaintext: String) -> Result<String> {
    use base64::Engine;
    with_state(|state| {
        let mls = get_mls(state)?;
        let ct = mls.encrypt(&group_id, plaintext.as_bytes())?;
        Ok(base64::engine::general_purpose::STANDARD.encode(&ct))
    })
}

/// Decrypt MLS ciphertext (base64). Returns plaintext + sender_id.
pub fn mls_decrypt(group_id: String, ciphertext_base64: String) -> Result<V2MlsDecryptResult> {
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
pub fn mls_remove_members(group_id: String, member_ids_json: String) -> Result<String> {
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
pub fn mls_self_update(group_id: String) -> Result<String> {
    use base64::Engine;
    with_state(|state| {
        let mls = get_mls(state)?;
        let commit = mls.self_update(&group_id)?;
        Ok(base64::engine::general_purpose::STANDARD.encode(&commit))
    })
}

/// Leave a group. Returns proposal base64.
pub fn mls_leave_group(group_id: String) -> Result<String> {
    use base64::Engine;
    with_state(|state| {
        let mls = get_mls(state)?;
        let proposal = mls.leave_group(&group_id)?;
        Ok(base64::engine::general_purpose::STANDARD.encode(&proposal))
    })
}

/// Process incoming MLS Commit (base64).
pub fn mls_process_commit(group_id: String, commit_base64: String) -> Result<()> {
    use base64::Engine;
    with_state(|state| {
        let mls = get_mls(state)?;
        let bytes = base64::engine::general_purpose::STANDARD.decode(&commit_base64)?;
        mls.process_commit(&group_id, &bytes)?;
        Ok(())
    })
}

/// Derive shared MLS temp inbox address.
pub fn mls_derive_temp_inbox(group_id: String) -> Result<String> {
    with_state(|state| {
        let mls = get_mls(state)?;
        Ok(mls.derive_temp_inbox(&group_id)?)
    })
}

/// List group members (nostr IDs).
pub fn mls_group_members(group_id: String) -> Result<Vec<String>> {
    with_state(|state| {
        let mls = get_mls(state)?;
        Ok(mls.group_members(&group_id)?)
    })
}

/// Update group context. Returns commit base64.
pub fn mls_update_group(
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
pub fn mls_group_info(group_id: String) -> Result<V2MlsGroupInfo> {
    with_state(|state| {
        let mls = get_mls(state)?;
        let ext = mls.group_extension(&group_id)?;
        Ok(V2MlsGroupInfo {
            name: String::from_utf8_lossy(&ext.name).to_string(),
            status: String::from_utf8_lossy(&ext.status).to_string(),
            admins_json: serde_json::to_string(
                &ext.admin_pubkeys
                    .iter()
                    .map(|k| hex::encode(k))
                    .collect::<Vec<_>>(),
            )?,
        })
    })
}
