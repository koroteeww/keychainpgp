//! WebAssembly bindings for KeychainPGP cryptographic operations.
//!
//! Exposes the core PGP engine to JavaScript via `wasm-bindgen`.

use wasm_bindgen::prelude::*;

use keychainpgp_core::engine::CryptoEngine;
use keychainpgp_core::sequoia_engine::SequoiaEngine;
use keychainpgp_core::types::{KeyGenOptions, UserId};
use secrecy::ExposeSecret;
use serde::Serialize;

/// Initialize the WASM module (sets up panic hook for better error messages).
#[wasm_bindgen]
pub fn init() {
    console_error_panic_hook::set_once();
}

/// Result of key generation, returned as a JS object.
///
/// **Security note:** `secret_key` is returned as a `Uint8Array` so that
/// JavaScript callers can zeroize it after use (`.fill(0)`).  JS strings
/// are immutable and managed by the GC — they cannot be reliably erased
/// from memory.
#[derive(Serialize)]
struct KeyPairResult {
    public_key: String,
    #[serde(with = "serde_bytes")]
    secret_key: Vec<u8>,
    fingerprint: String,
}

/// Result of signature verification, returned as a JS object.
#[derive(Serialize)]
struct VerifyResultJs {
    valid: bool,
    signer_fingerprint: Option<String>,
}

/// Result of key inspection, returned as a JS object.
#[derive(Serialize)]
struct CertInfoJs {
    fingerprint: String,
    user_ids: Vec<UserIdJs>,
    algorithm: String,
    created_at: String,
    expires_at: Option<String>,
    has_secret_key: bool,
    subkeys: Vec<SubkeyInfoJs>,
}

#[derive(Serialize)]
struct UserIdJs {
    name: Option<String>,
    email: Option<String>,
}

#[derive(Serialize)]
struct SubkeyInfoJs {
    fingerprint: String,
    algorithm: String,
    created_at: String,
    expires_at: Option<String>,
    capabilities: Vec<String>,
    is_revoked: bool,
}

/// Generate a new PGP key pair.
///
/// Returns a JS object: `{ public_key: string, secret_key: string, fingerprint: string }`
#[wasm_bindgen(js_name = generateKeyPair)]
pub fn generate_key_pair(
    name: &str,
    email: &str,
    passphrase: Option<String>,
) -> Result<JsValue, JsError> {
    let engine = SequoiaEngine::new();
    let user_id = UserId::new(name, email);
    let mut options = KeyGenOptions::new(user_id);

    if let Some(pp) = passphrase {
        if !pp.is_empty() {
            options = options.with_passphrase(secrecy::SecretBox::new(Box::new(pp.into_bytes())));
        }
    }

    let key_pair = engine
        .generate_key_pair(options)
        .map_err(|e| JsError::new(&e.to_string()))?;

    let result = KeyPairResult {
        public_key: String::from_utf8_lossy(&key_pair.public_key).into_owned(),
        secret_key: key_pair.secret_key.expose_secret().clone(),
        fingerprint: key_pair.fingerprint.0.clone(),
    };

    serde_wasm_bindgen::to_value(&result).map_err(|e| JsError::new(&e.to_string()))
}

/// Encrypt plaintext for the given recipients.
///
/// `recipient_keys_json` is a JSON array of ASCII-armored public key strings.
/// Returns the ASCII-armored ciphertext.
#[wasm_bindgen(js_name = encrypt)]
pub fn encrypt(plaintext: &str, recipient_keys_json: &str) -> Result<String, JsError> {
    let engine = SequoiaEngine::new();

    let recipient_keys: Vec<String> =
        serde_json::from_str(recipient_keys_json).map_err(|e| JsError::new(&e.to_string()))?;

    let key_bytes: Vec<Vec<u8>> = recipient_keys.into_iter().map(|k| k.into_bytes()).collect();

    let ciphertext = engine
        .encrypt(plaintext.as_bytes(), &key_bytes)
        .map_err(|e| JsError::new(&e.to_string()))?;

    String::from_utf8(ciphertext).map_err(|e| JsError::new(&e.to_string()))
}

/// Decrypt an encrypted PGP message.
///
/// Returns the plaintext string.
#[wasm_bindgen(js_name = decrypt)]
pub fn decrypt(
    ciphertext: &str,
    secret_key: &str,
    passphrase: Option<String>,
) -> Result<String, JsError> {
    let engine = SequoiaEngine::new();

    let pp_bytes = passphrase.as_ref().map(|p| p.as_bytes());

    let plaintext = engine
        .decrypt(ciphertext.as_bytes(), secret_key.as_bytes(), pp_bytes)
        .map_err(|e| JsError::new(&e.to_string()))?;

    String::from_utf8(plaintext).map_err(|e| JsError::new(&e.to_string()))
}

/// Sign a message with the given secret key.
///
/// Returns the ASCII-armored signed message.
#[wasm_bindgen(js_name = sign)]
pub fn sign(data: &str, secret_key: &str, passphrase: Option<String>) -> Result<String, JsError> {
    let engine = SequoiaEngine::new();

    let pp_bytes = passphrase.as_ref().map(|p| p.as_bytes());

    let signed = engine
        .sign(data.as_bytes(), secret_key.as_bytes(), pp_bytes)
        .map_err(|e| JsError::new(&e.to_string()))?;

    String::from_utf8(signed).map_err(|e| JsError::new(&e.to_string()))
}

/// Verify a signed PGP message against a signer's public key.
///
/// Returns a JS object: `{ valid: boolean, signer_fingerprint: string | null }`
#[wasm_bindgen(js_name = verify)]
pub fn verify(signed_data: &str, signer_key: &str) -> Result<JsValue, JsError> {
    let engine = SequoiaEngine::new();

    let result = engine
        .verify(signed_data.as_bytes(), signer_key.as_bytes())
        .map_err(|e| JsError::new(&e.to_string()))?;

    let js_result = VerifyResultJs {
        valid: result.valid,
        signer_fingerprint: result.signer_fingerprint,
    };

    serde_wasm_bindgen::to_value(&js_result).map_err(|e| JsError::new(&e.to_string()))
}

/// Inspect a PGP key and extract metadata.
///
/// Returns a JS object with key information (fingerprint, user IDs, algorithm, dates, subkeys).
#[wasm_bindgen(js_name = inspectKey)]
pub fn inspect_key(key_data: &str) -> Result<JsValue, JsError> {
    let engine = SequoiaEngine::new();

    let info = engine
        .inspect_key(key_data.as_bytes())
        .map_err(|e| JsError::new(&e.to_string()))?;

    let js_info = CertInfoJs {
        fingerprint: info.fingerprint.0,
        user_ids: info
            .user_ids
            .into_iter()
            .map(|uid| UserIdJs {
                name: uid.name,
                email: uid.email,
            })
            .collect(),
        algorithm: info.algorithm.to_string(),
        created_at: info.created_at,
        expires_at: info.expires_at,
        has_secret_key: info.has_secret_key,
        subkeys: info
            .subkeys
            .into_iter()
            .map(|sk| SubkeyInfoJs {
                fingerprint: sk.fingerprint,
                algorithm: sk.algorithm,
                created_at: sk.created_at,
                expires_at: sk.expires_at,
                capabilities: sk.capabilities.into_iter().map(|c| c.to_string()).collect(),
                is_revoked: sk.is_revoked,
            })
            .collect(),
    };

    serde_wasm_bindgen::to_value(&js_info).map_err(|e| JsError::new(&e.to_string()))
}

/// Native tests exercising the same crypto operations as the WASM bindings.
///
/// These run with `cargo test -p keychainpgp-wasm` (no browser needed) and
/// validate the Rust layer that backs every JS-exposed function.
#[cfg(test)]
mod tests {
    use keychainpgp_core::engine::CryptoEngine;
    use keychainpgp_core::sequoia_engine::SequoiaEngine;
    use keychainpgp_core::types::{KeyGenOptions, UserId};
    use secrecy::ExposeSecret;

    /// Helper: generate a key pair, return (public_key string, secret_key string, fingerprint).
    fn gen_key(name: &str, email: &str) -> (String, String, String) {
        gen_key_with_passphrase(name, email, None)
    }

    fn gen_key_with_passphrase(
        name: &str,
        email: &str,
        passphrase: Option<&str>,
    ) -> (String, String, String) {
        let engine = SequoiaEngine::new();
        let mut options = KeyGenOptions::new(UserId::new(name, email));
        if let Some(pp) = passphrase {
            options =
                options.with_passphrase(secrecy::SecretBox::new(Box::new(pp.as_bytes().to_vec())));
        }
        let kp = engine.generate_key_pair(options).unwrap();

        let public_key = String::from_utf8_lossy(&kp.public_key).into_owned();
        // Replicate the WASM path: secret_key is Vec<u8> (serde_bytes → Uint8Array)
        // then JS does TextDecoder.decode() which is equivalent to String::from_utf8.
        let secret_key_bytes = kp.secret_key.expose_secret().clone();
        let secret_key = String::from_utf8(secret_key_bytes).unwrap();
        let fingerprint = kp.fingerprint.0.clone();

        (public_key, secret_key, fingerprint)
    }

    #[test]
    fn test_keygen_produces_valid_armor() {
        let (public_key, secret_key, fingerprint) = gen_key("Test", "test@example.com");

        assert!(public_key.contains("BEGIN PGP PUBLIC KEY BLOCK"));
        assert!(secret_key.contains("BEGIN PGP PRIVATE KEY BLOCK"));
        assert!(!fingerprint.is_empty());
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let (public_key, secret_key, _) = gen_key("Alice", "alice@example.com");
        let engine = SequoiaEngine::new();

        let plaintext = "Hello from WASM native test!";
        let ciphertext = engine
            .encrypt(plaintext.as_bytes(), &[public_key.into_bytes()])
            .unwrap();
        let ciphertext_str = String::from_utf8(ciphertext).unwrap();
        assert!(ciphertext_str.contains("BEGIN PGP MESSAGE"));

        // Decrypt using the same bytes→string→bytes path as the web app
        let decrypted = engine
            .decrypt(ciphertext_str.as_bytes(), secret_key.as_bytes(), None)
            .unwrap();
        assert_eq!(decrypted, plaintext.as_bytes());
    }

    #[test]
    fn test_encrypt_decrypt_with_passphrase() {
        let (public_key, secret_key, _) =
            gen_key_with_passphrase("Bob", "bob@example.com", Some("my-passphrase"));
        let engine = SequoiaEngine::new();

        let plaintext = "Passphrase-protected";
        let ciphertext = engine
            .encrypt(plaintext.as_bytes(), &[public_key.into_bytes()])
            .unwrap();

        // With correct passphrase
        let decrypted = engine
            .decrypt(&ciphertext, secret_key.as_bytes(), Some(b"my-passphrase"))
            .unwrap();
        assert_eq!(decrypted, plaintext.as_bytes());

        // Without passphrase should fail
        let result = engine.decrypt(&ciphertext, secret_key.as_bytes(), None);
        assert!(result.is_err());

        // Wrong passphrase should fail
        let result = engine.decrypt(&ciphertext, secret_key.as_bytes(), Some(b"wrong"));
        assert!(result.is_err());
    }

    #[test]
    fn test_sign_verify_roundtrip() {
        let (public_key, secret_key, _) = gen_key("Signer", "signer@example.com");
        let engine = SequoiaEngine::new();

        let message = "This message is authentic.";
        let signed = engine
            .sign(message.as_bytes(), secret_key.as_bytes(), None)
            .unwrap();
        let signed_str = String::from_utf8(signed).unwrap();
        assert!(signed_str.contains("BEGIN PGP MESSAGE"));

        let result = engine
            .verify(signed_str.as_bytes(), public_key.as_bytes())
            .unwrap();
        assert!(result.valid);
    }

    #[test]
    fn test_inspect_key() {
        let (public_key, _, _) = gen_key("Alice Inspect", "alice@inspect.com");
        let engine = SequoiaEngine::new();

        let info = engine.inspect_key(public_key.as_bytes()).unwrap();
        assert!(!info.fingerprint.0.is_empty());
        assert!(!info.has_secret_key); // public key only
        assert_eq!(info.user_ids[0].name.as_deref(), Some("Alice Inspect"));
        assert_eq!(info.user_ids[0].email.as_deref(), Some("alice@inspect.com"));
    }

    #[test]
    fn test_inspect_secret_key() {
        let (_, secret_key, _) = gen_key("Bob Inspect", "bob@inspect.com");
        let engine = SequoiaEngine::new();

        let info = engine.inspect_key(secret_key.as_bytes()).unwrap();
        assert!(info.has_secret_key);
    }

    #[test]
    fn test_decrypt_wrong_key_fails() {
        let (pub_alice, _, _) = gen_key("Alice", "alice@example.com");
        let (_, sec_bob, _) = gen_key("Bob", "bob@example.com");
        let engine = SequoiaEngine::new();

        let ciphertext = engine
            .encrypt(b"For Alice only", &[pub_alice.into_bytes()])
            .unwrap();

        let result = engine.decrypt(&ciphertext, sec_bob.as_bytes(), None);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_wrong_key_fails() {
        let (_, sec_alice, _) = gen_key("Alice", "alice@example.com");
        let (pub_bob, _, _) = gen_key("Bob", "bob@example.com");
        let engine = SequoiaEngine::new();

        let signed = engine
            .sign(b"Signed by Alice", sec_alice.as_bytes(), None)
            .unwrap();

        let result = engine.verify(&signed, pub_bob.as_bytes()).unwrap();
        assert!(!result.valid);
    }

    /// Test the exact bytes→string conversion that the web app performs.
    /// This is the path that broke on Chrome Mac: WASM returns secret_key as
    /// Vec<u8> (Uint8Array via serde_bytes), JS does TextDecoder.decode(),
    /// then passes the string back to WASM decrypt.
    #[test]
    fn test_secret_key_bytes_to_string_roundtrip() {
        let engine = SequoiaEngine::new();
        let kp = engine
            .generate_key_pair(KeyGenOptions::new(UserId::new("Roundtrip", "rt@test.com")))
            .unwrap();

        let plaintext = b"Testing the bytes-to-string roundtrip";
        let ciphertext = engine.encrypt(plaintext, &[kp.public_key.clone()]).unwrap();

        // Simulate the WASM/JS pipeline:
        // 1. Rust returns secret_key as Vec<u8> (serde_bytes → Uint8Array in JS)
        let secret_bytes: Vec<u8> = kp.secret_key.expose_secret().clone();
        // 2. JS does: new TextDecoder().decode(uint8array) → string
        let secret_string = String::from_utf8(secret_bytes).unwrap();
        // 3. JS passes string to WASM decrypt, wasm-bindgen converts &str → bytes
        let decrypted = engine
            .decrypt(&ciphertext, secret_string.as_bytes(), None)
            .unwrap();

        assert_eq!(decrypted, plaintext);
    }

    /// Test the JSON recipient parsing used by the WASM encrypt wrapper.
    #[test]
    fn test_recipient_keys_json_parsing() {
        let (pub1, _, _) = gen_key("R1", "r1@test.com");
        let (pub2, _, _) = gen_key("R2", "r2@test.com");

        let json = serde_json::to_string(&vec![&pub1, &pub2]).unwrap();
        let parsed: Vec<String> = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.len(), 2);
        assert!(parsed[0].contains("BEGIN PGP PUBLIC KEY BLOCK"));
        assert!(parsed[1].contains("BEGIN PGP PUBLIC KEY BLOCK"));
    }

    #[test]
    fn test_full_roundtrip_two_parties() {
        let (pub_sender, sec_sender, _) = gen_key("Sender", "sender@test.com");
        let (pub_recipient, sec_recipient, _) = gen_key("Recipient", "recipient@test.com");
        let engine = SequoiaEngine::new();

        let plaintext = "Confidential message";

        // Encrypt for recipient
        let ciphertext = engine
            .encrypt(plaintext.as_bytes(), &[pub_recipient.as_bytes().to_vec()])
            .unwrap();

        // Recipient decrypts
        let decrypted = engine
            .decrypt(&ciphertext, sec_recipient.as_bytes(), None)
            .unwrap();
        assert_eq!(decrypted, plaintext.as_bytes());

        // Sender cannot decrypt
        assert!(
            engine
                .decrypt(&ciphertext, sec_sender.as_bytes(), None)
                .is_err()
        );

        // Sender signs
        let signed = engine
            .sign(plaintext.as_bytes(), sec_sender.as_bytes(), None)
            .unwrap();

        // Verify with sender's key → valid
        let v1 = engine.verify(&signed, pub_sender.as_bytes()).unwrap();
        assert!(v1.valid);

        // Verify with recipient's key → invalid
        let v2 = engine.verify(&signed, pub_recipient.as_bytes()).unwrap();
        assert!(!v2.valid);
    }
}
