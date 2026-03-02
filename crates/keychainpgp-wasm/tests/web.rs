//! Browser-based WASM tests for keychainpgp-wasm.

use wasm_bindgen::JsValue;
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

use keychainpgp_wasm::*;

/// Extract a string field from a JS object.
fn get_string(obj: &JsValue, key: &str) -> String {
    js_sys::Reflect::get(obj, &JsValue::from_str(key))
        .unwrap()
        .as_string()
        .unwrap()
}

/// Extract the secret_key field (Uint8Array via serde_bytes) and decode to String.
fn get_secret_key(obj: &JsValue) -> String {
    let val = js_sys::Reflect::get(obj, &JsValue::from_str("secret_key")).unwrap();
    let array = js_sys::Uint8Array::from(val);
    String::from_utf8(array.to_vec()).unwrap()
}

#[wasm_bindgen_test]
fn test_init() {
    init();
}

#[wasm_bindgen_test]
fn test_keygen_encrypt_decrypt_roundtrip() {
    init();

    // Generate a key pair
    let kp_js = generate_key_pair("Test User", "test@example.com", None).unwrap();

    let public_key = get_string(&kp_js, "public_key");
    let secret_key = get_secret_key(&kp_js);
    let fingerprint = get_string(&kp_js, "fingerprint");

    assert!(!fingerprint.is_empty());
    assert!(public_key.contains("BEGIN PGP PUBLIC KEY BLOCK"));
    assert!(secret_key.contains("BEGIN PGP PRIVATE KEY BLOCK"));

    // Encrypt
    let plaintext = "Hello from WASM!";
    let recipient_keys_json = format!("[{:?}]", public_key);
    let ciphertext = encrypt(plaintext, &recipient_keys_json).unwrap();
    assert!(ciphertext.contains("BEGIN PGP MESSAGE"));

    // Decrypt
    let decrypted = decrypt(&ciphertext, &secret_key, None).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[wasm_bindgen_test]
fn test_sign_verify_roundtrip() {
    init();

    let kp_js = generate_key_pair("Signer", "signer@example.com", None).unwrap();

    let public_key = get_string(&kp_js, "public_key");
    let secret_key = get_secret_key(&kp_js);

    // Sign
    let message = "This message is authentic.";
    let signed = sign(message, &secret_key, None).unwrap();
    assert!(signed.contains("BEGIN PGP MESSAGE"));

    // Verify
    let verify_js = verify(&signed, &public_key).unwrap();
    let valid = js_sys::Reflect::get(&verify_js, &JsValue::from_str("valid"))
        .unwrap()
        .as_bool()
        .unwrap();
    assert!(valid);
}

#[wasm_bindgen_test]
fn test_inspect_key() {
    init();

    let kp_js = generate_key_pair("Alice", "alice@example.com", None).unwrap();

    let public_key = get_string(&kp_js, "public_key");

    let info_js = inspect_key(&public_key).unwrap();
    let fingerprint = js_sys::Reflect::get(&info_js, &JsValue::from_str("fingerprint"))
        .unwrap()
        .as_string()
        .unwrap();
    let has_secret_key = js_sys::Reflect::get(&info_js, &JsValue::from_str("has_secret_key"))
        .unwrap()
        .as_bool()
        .unwrap();

    assert!(!fingerprint.is_empty());
    assert!(!has_secret_key);
}

#[wasm_bindgen_test]
fn test_keygen_with_passphrase() {
    init();

    let kp_js = generate_key_pair(
        "Protected",
        "protected@example.com",
        Some("my-passphrase".into()),
    )
    .unwrap();

    let public_key = get_string(&kp_js, "public_key");
    let secret_key = get_secret_key(&kp_js);

    // Encrypt with public key
    let ciphertext = encrypt("secret", &format!("[{:?}]", public_key)).unwrap();

    // Decrypt with passphrase
    let decrypted = decrypt(&ciphertext, &secret_key, Some("my-passphrase".into())).unwrap();
    assert_eq!(decrypted, "secret");

    // Decrypt without passphrase should fail
    let result = decrypt(&ciphertext, &secret_key, None);
    assert!(result.is_err());
}

#[wasm_bindgen_test]
fn test_full_crypto_roundtrip() {
    init();

    // Generate two key pairs: sender and recipient
    let sender_js = generate_key_pair("Sender", "sender@example.com", None).unwrap();
    let recipient_js = generate_key_pair("Recipient", "recipient@example.com", None).unwrap();

    let sender_public = get_string(&sender_js, "public_key");
    let sender_secret = get_secret_key(&sender_js);
    let recipient_public = get_string(&recipient_js, "public_key");
    let recipient_secret = get_secret_key(&recipient_js);

    let plaintext = "Confidential message from Sender to Recipient";

    // Encrypt for recipient
    let ciphertext = encrypt(plaintext, &format!("[{:?}]", recipient_public)).unwrap();
    assert!(ciphertext.contains("BEGIN PGP MESSAGE"));

    // Recipient decrypts
    let decrypted = decrypt(&ciphertext, &recipient_secret, None).unwrap();
    assert_eq!(decrypted, plaintext);

    // Sender cannot decrypt (wrong key)
    let wrong_key_result = decrypt(&ciphertext, &sender_secret, None);
    assert!(wrong_key_result.is_err());

    // Sign by sender
    let signed = sign(plaintext, &sender_secret, None).unwrap();
    assert!(signed.contains("BEGIN PGP MESSAGE"));

    // Verify with sender's public key
    let verify_result = verify(&signed, &sender_public).unwrap();
    let valid = js_sys::Reflect::get(&verify_result, &JsValue::from_str("valid"))
        .unwrap()
        .as_bool()
        .unwrap();
    assert!(valid);

    // Verify with wrong key should fail
    let wrong_verify = verify(&signed, &recipient_public).unwrap();
    let wrong_valid = js_sys::Reflect::get(&wrong_verify, &JsValue::from_str("valid"))
        .unwrap()
        .as_bool()
        .unwrap();
    assert!(!wrong_valid);
}
