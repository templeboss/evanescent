use anyhow::{bail, Result};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

/// HKDF info strings — must match exactly across all components (standards.md §7, §2).
const AUTH_PREFIX: &[u8] = b"Evanescent_Auth_v1";
const SPK_PREFIX: &[u8] = b"Evanescent_SPK_v1";

/// Verify the challenge-response authentication signature.
///
/// message = "Evanescent_Auth_v1" || nonce
pub fn verify_auth(identity_key: &[u8], nonce: &[u8], signature: &[u8]) -> Result<()> {
    if identity_key.len() != 32 {
        bail!("identity key must be 32 bytes");
    }
    if nonce.len() != 32 {
        bail!("nonce must be 32 bytes");
    }
    if signature.len() != 64 {
        bail!("signature must be 64 bytes");
    }

    let vk = VerifyingKey::from_bytes(identity_key.try_into().unwrap())
        .map_err(|e| anyhow::anyhow!("invalid identity key: {e}"))?;
    let sig = Signature::from_bytes(signature.try_into().unwrap());

    let mut msg = Vec::with_capacity(AUTH_PREFIX.len() + 32);
    msg.extend_from_slice(AUTH_PREFIX);
    msg.extend_from_slice(nonce);

    vk.verify(&msg, &sig)
        .map_err(|_| anyhow::anyhow!("signature verification failed"))
}

/// Verify a signed prekey signature.
///
/// message = "Evanescent_SPK_v1" || spk_public_bytes
pub fn verify_spk(identity_key: &[u8], spk_public: &[u8], signature: &[u8]) -> Result<()> {
    if identity_key.len() != 32 {
        bail!("identity key must be 32 bytes");
    }
    if spk_public.len() != 32 {
        bail!("SPK public key must be 32 bytes");
    }
    if signature.len() != 64 {
        bail!("signature must be 64 bytes");
    }

    let vk = VerifyingKey::from_bytes(identity_key.try_into().unwrap())
        .map_err(|e| anyhow::anyhow!("invalid identity key: {e}"))?;
    let sig = Signature::from_bytes(signature.try_into().unwrap());

    let mut msg = Vec::with_capacity(SPK_PREFIX.len() + 32);
    msg.extend_from_slice(SPK_PREFIX);
    msg.extend_from_slice(spk_public);

    vk.verify(&msg, &sig)
        .map_err(|_| anyhow::anyhow!("SPK signature verification failed"))
}

/// Derive the hex mailbox address from an Ed25519 public key using BLAKE3.
/// Output: first 32 bytes of BLAKE3 hash, hex-encoded (64 hex chars).
/// Must match Android's mailbox_addr_from_key implementation (standards.md §8).
pub fn mailbox_addr_from_key(identity_key: &[u8]) -> String {
    let hash = blake3::hash(identity_key);
    hex::encode(&hash.as_bytes()[..32])
}
