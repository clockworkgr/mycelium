//! Group discovery key derivation from shared passphrases.

use hkdf::Hkdf;
use sha2::Sha256;

/// Derive a 32-byte group discovery key from a passphrase using HKDF.
///
/// Same passphrase always produces the same key, enabling mutual
/// recognition via truncated hash in beacon frames.
pub fn derive_group_discovery_key(passphrase: &str) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, passphrase.as_bytes());
    let mut key = [0u8; 32];
    hk.expand(b"MyceliumGroupDiscovery", &mut key)
        .expect("HKDF expansion failed");
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_same_passphrase_same_key() {
        let k1 = derive_group_discovery_key("secret community");
        let k2 = derive_group_discovery_key("secret community");
        assert_eq!(k1, k2);
    }

    #[test]
    fn test_different_passphrase_different_key() {
        let k1 = derive_group_discovery_key("secret community");
        let k2 = derive_group_discovery_key("other community");
        assert_ne!(k1, k2);
    }

    #[test]
    fn test_key_is_nonzero() {
        let k = derive_group_discovery_key("test");
        assert_ne!(k, [0u8; 32]);
    }
}
