use anyhow::{Context, Result, bail};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use rand::RngCore;
use rand_core::OsRng;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

const BLOB_MAGIC: &[u8] = b"ARCAE1";
const WRAP_MAGIC: &[u8] = b"ARCAW1";
const SECRET_MAGIC: &[u8] = b"ARCAS1";
const COMPRESSED_MAGIC: &[u8] = b"ARCAC1";
const NONCE_LEN: usize = 24;
const KEY_LEN: usize = 32;
const PUBKEY_LEN: usize = 32;
const SECRET_SALT_LEN: usize = 16;
const DEFAULT_ZSTD_LEVEL: i32 = 19;

pub struct EncryptedPayload {
    pub blob: Vec<u8>,
    pub owner_wrapped_key_b64: String,
    pub compressed: bool,
    pub secret_protected: bool,
}

pub fn derive_identity_keypair(
    username: &str,
    server_url: &str,
    password: &str,
) -> Result<(String, String)> {
    let salt_hash = blake3::hash(format!("arca-identity-salt:{username}:{server_url}").as_bytes());
    let salt = &salt_hash.as_bytes()[..16];
    let params = Params::new(64 * 1024, 3, 1, Some(KEY_LEN))
        .map_err(|error| anyhow::anyhow!("Parametres Argon2 invalides: {error}"))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut output = [0_u8; KEY_LEN];
    argon
        .hash_password_into(password.as_bytes(), salt, &mut output)
        .map_err(|error| anyhow::anyhow!("Derivation Argon2 impossible: {error}"))?;

    let secret = StaticSecret::from(output);
    let public = PublicKey::from(&secret);

    Ok((
        STANDARD.encode(secret.to_bytes()),
        STANDARD.encode(public.as_bytes()),
    ))
}

pub fn encrypt_for_upload(
    owner_public_key_b64: &str,
    remote_path: &str,
    plaintext: &[u8],
) -> Result<EncryptedPayload> {
    encrypt_for_upload_with_options(owner_public_key_b64, remote_path, plaintext, None)
}

pub fn encrypt_for_upload_with_options(
    owner_public_key_b64: &str,
    remote_path: &str,
    plaintext: &[u8],
    secret_password: Option<&str>,
) -> Result<EncryptedPayload> {
    let (prepared_plaintext, compressed) = compress_for_upload(plaintext)?;
    let secret_protected = secret_password.is_some();
    let inner_plaintext = match secret_password {
        Some(password) => protect_with_secret(remote_path, &prepared_plaintext, password)?,
        None => prepared_plaintext,
    };
    let file_key = random_key();
    let blob = encrypt_with_file_key(&file_key, remote_path, &inner_plaintext)?;
    let owner_wrapped_key_b64 = wrap_file_key(&file_key, remote_path, owner_public_key_b64)?;

    Ok(EncryptedPayload {
        blob,
        owner_wrapped_key_b64,
        compressed,
        secret_protected,
    })
}

pub fn decrypt_downloaded_blob_with_secret(
    private_key_b64: &str,
    remote_path: &str,
    wrapped_key_b64: &str,
    blob: &[u8],
    secret_password: Option<&str>,
) -> Result<Vec<u8>> {
    let file_key = unwrap_file_key(private_key_b64, remote_path, wrapped_key_b64)?;
    let mut plaintext = decrypt_with_file_key(&file_key, remote_path, blob)?;

    if is_secret_protected_blob(&plaintext) {
        let password = secret_password.ok_or_else(|| {
            anyhow::anyhow!(
                "Ce fichier requiert un mot de passe secret. Reutilise la commande avec le prompt secret."
            )
        })?;
        plaintext = unprotect_with_secret(remote_path, &plaintext, password)?;
    }

    if is_compressed_blob(&plaintext) {
        plaintext = decompress_after_download(&plaintext)?;
    }

    Ok(plaintext)
}

pub fn unwrap_for_reshare(
    private_key_b64: &str,
    remote_path: &str,
    wrapped_key_b64: &str,
) -> Result<[u8; KEY_LEN]> {
    unwrap_file_key(private_key_b64, remote_path, wrapped_key_b64)
}

pub fn wrap_file_key(
    file_key: &[u8; KEY_LEN],
    remote_path: &str,
    public_key_b64: &str,
) -> Result<String> {
    let recipient_public = decode_public_key(public_key_b64)?;
    let ephemeral_secret = StaticSecret::random_from_rng(OsRng);
    let ephemeral_public = PublicKey::from(&ephemeral_secret);
    let shared_secret = ephemeral_secret.diffie_hellman(&recipient_public);
    let wrapping_key = derive_wrapping_key(shared_secret.as_bytes(), remote_path)?;
    let mut nonce_bytes = [0_u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&wrapping_key));

    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce_bytes),
            Payload {
                msg: file_key,
                aad: remote_path.as_bytes(),
            },
        )
        .map_err(|_| anyhow::anyhow!("Encapsulation de cle impossible"))?;

    let mut blob = Vec::with_capacity(WRAP_MAGIC.len() + PUBKEY_LEN + NONCE_LEN + ciphertext.len());
    blob.extend_from_slice(WRAP_MAGIC);
    blob.extend_from_slice(ephemeral_public.as_bytes());
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ciphertext);
    Ok(STANDARD.encode(blob))
}

pub fn decode_public_key(public_key_b64: &str) -> Result<PublicKey> {
    let bytes = STANDARD
        .decode(public_key_b64.as_bytes())
        .context("Cle publique E2EE invalide")?;
    if bytes.len() != PUBKEY_LEN {
        bail!("Longueur de cle publique invalide");
    }

    let mut array = [0_u8; PUBKEY_LEN];
    array.copy_from_slice(&bytes);
    Ok(PublicKey::from(array))
}

fn unwrap_file_key(
    private_key_b64: &str,
    remote_path: &str,
    wrapped_key_b64: &str,
) -> Result<[u8; KEY_LEN]> {
    let private_key = decode_private_key(private_key_b64)?;
    let wrapped = STANDARD
        .decode(wrapped_key_b64.as_bytes())
        .context("Cle encapsulee invalide")?;

    if wrapped.len() <= WRAP_MAGIC.len() + PUBKEY_LEN + NONCE_LEN {
        bail!("Cle encapsulee trop courte");
    }
    if &wrapped[..WRAP_MAGIC.len()] != WRAP_MAGIC {
        bail!("Format de cle encapsulee inconnu");
    }

    let public_start = WRAP_MAGIC.len();
    let public_end = public_start + PUBKEY_LEN;
    let nonce_end = public_end + NONCE_LEN;

    let mut sender_pub = [0_u8; PUBKEY_LEN];
    sender_pub.copy_from_slice(&wrapped[public_start..public_end]);
    let sender_public = PublicKey::from(sender_pub);
    let shared_secret = private_key.diffie_hellman(&sender_public);
    let wrapping_key = derive_wrapping_key(shared_secret.as_bytes(), remote_path)?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&wrapping_key));

    let file_key = cipher
        .decrypt(
            XNonce::from_slice(&wrapped[public_end..nonce_end]),
            Payload {
                msg: &wrapped[nonce_end..],
                aad: remote_path.as_bytes(),
            },
        )
        .map_err(|_| anyhow::anyhow!("Ouverture de cle impossible"))?;

    if file_key.len() != KEY_LEN {
        bail!("Taille de cle de fichier invalide");
    }

    let mut key = [0_u8; KEY_LEN];
    key.copy_from_slice(&file_key);
    Ok(key)
}

fn encrypt_with_file_key(
    file_key: &[u8; KEY_LEN],
    remote_path: &str,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(file_key));
    let mut nonce_bytes = [0_u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);

    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce_bytes),
            Payload {
                msg: plaintext,
                aad: remote_path.as_bytes(),
            },
        )
        .map_err(|_| anyhow::anyhow!("Chiffrement impossible"))?;

    let mut blob = Vec::with_capacity(BLOB_MAGIC.len() + NONCE_LEN + ciphertext.len());
    blob.extend_from_slice(BLOB_MAGIC);
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ciphertext);
    Ok(blob)
}

fn decrypt_with_file_key(
    file_key: &[u8; KEY_LEN],
    remote_path: &str,
    blob: &[u8],
) -> Result<Vec<u8>> {
    if blob.len() <= BLOB_MAGIC.len() + NONCE_LEN {
        bail!("Blob chiffre trop court");
    }
    if &blob[..BLOB_MAGIC.len()] != BLOB_MAGIC {
        bail!("Format E2EE inconnu");
    }

    let nonce_start = BLOB_MAGIC.len();
    let nonce_end = nonce_start + NONCE_LEN;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(file_key));

    cipher
        .decrypt(
            XNonce::from_slice(&blob[nonce_start..nonce_end]),
            Payload {
                msg: &blob[nonce_end..],
                aad: remote_path.as_bytes(),
            },
        )
        .map_err(|_| anyhow::anyhow!("Dechiffrement impossible"))
}

fn derive_wrapping_key(shared_secret: &[u8], remote_path: &str) -> Result<[u8; KEY_LEN]> {
    let hkdf = Hkdf::<Sha256>::new(None, shared_secret);
    let mut key = [0_u8; KEY_LEN];
    hkdf.expand(format!("arca-wrap-key:{remote_path}").as_bytes(), &mut key)
        .map_err(|_| anyhow::anyhow!("Derivation HKDF impossible"))?;
    Ok(key)
}

fn decode_private_key(private_key_b64: &str) -> Result<StaticSecret> {
    let bytes = STANDARD
        .decode(private_key_b64.as_bytes())
        .context("Cle privee E2EE invalide")?;
    if bytes.len() != KEY_LEN {
        bail!("Longueur de cle privee invalide");
    }

    let mut array = [0_u8; KEY_LEN];
    array.copy_from_slice(&bytes);
    Ok(StaticSecret::from(array))
}

fn random_key() -> [u8; KEY_LEN] {
    let mut key = [0_u8; KEY_LEN];
    rand::thread_rng().fill_bytes(&mut key);
    key
}

fn compress_for_upload(plaintext: &[u8]) -> Result<(Vec<u8>, bool)> {
    let compressed = zstd::stream::encode_all(std::io::Cursor::new(plaintext), DEFAULT_ZSTD_LEVEL)
        .context("Compression zstd impossible")?;
    if compressed.len() >= plaintext.len() {
        return Ok((plaintext.to_vec(), false));
    }

    let mut wrapped = Vec::with_capacity(COMPRESSED_MAGIC.len() + compressed.len());
    wrapped.extend_from_slice(COMPRESSED_MAGIC);
    wrapped.extend_from_slice(&compressed);
    Ok((wrapped, true))
}

fn decompress_after_download(blob: &[u8]) -> Result<Vec<u8>> {
    if !is_compressed_blob(blob) {
        return Ok(blob.to_vec());
    }
    zstd::stream::decode_all(std::io::Cursor::new(&blob[COMPRESSED_MAGIC.len()..]))
        .context("Decompression zstd impossible")
}

fn is_compressed_blob(blob: &[u8]) -> bool {
    blob.starts_with(COMPRESSED_MAGIC)
}

fn protect_with_secret(remote_path: &str, plaintext: &[u8], password: &str) -> Result<Vec<u8>> {
    let mut salt = [0_u8; SECRET_SALT_LEN];
    rand::thread_rng().fill_bytes(&mut salt);
    let key = derive_secret_key(password, &salt)?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
    let mut nonce_bytes = [0_u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce_bytes),
            Payload {
                msg: plaintext,
                aad: remote_path.as_bytes(),
            },
        )
        .map_err(|_| anyhow::anyhow!("Chiffrement secret impossible"))?;

    let mut blob =
        Vec::with_capacity(SECRET_MAGIC.len() + SECRET_SALT_LEN + NONCE_LEN + ciphertext.len());
    blob.extend_from_slice(SECRET_MAGIC);
    blob.extend_from_slice(&salt);
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ciphertext);
    Ok(blob)
}

fn unprotect_with_secret(remote_path: &str, blob: &[u8], password: &str) -> Result<Vec<u8>> {
    if blob.len() <= SECRET_MAGIC.len() + SECRET_SALT_LEN + NONCE_LEN {
        bail!("Blob secret trop court");
    }
    if !blob.starts_with(SECRET_MAGIC) {
        bail!("Format secret inconnu");
    }
    let salt_start = SECRET_MAGIC.len();
    let salt_end = salt_start + SECRET_SALT_LEN;
    let nonce_end = salt_end + NONCE_LEN;
    let key = derive_secret_key(password, &blob[salt_start..salt_end])?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
    cipher
        .decrypt(
            XNonce::from_slice(&blob[salt_end..nonce_end]),
            Payload {
                msg: &blob[nonce_end..],
                aad: remote_path.as_bytes(),
            },
        )
        .map_err(|_| anyhow::anyhow!("Mot de passe secret invalide ou blob corrompu"))
}

fn derive_secret_key(password: &str, salt: &[u8]) -> Result<[u8; KEY_LEN]> {
    let params = Params::new(64 * 1024, 3, 1, Some(KEY_LEN))
        .map_err(|error| anyhow::anyhow!("Parametres Argon2 invalides: {error}"))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut output = [0_u8; KEY_LEN];
    argon
        .hash_password_into(password.as_bytes(), salt, &mut output)
        .map_err(|error| anyhow::anyhow!("Derivation du mot de passe secret impossible: {error}"))?;
    Ok(output)
}

fn is_secret_protected_blob(blob: &[u8]) -> bool {
    blob.starts_with(SECRET_MAGIC)
}
