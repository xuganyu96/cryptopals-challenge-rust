//! Some of the test might be slow when running in debug mode;
//! use "cargo test --profile release" to speed up prime generations
use crypto_bigint::{NonZero, U2048};
use cryptopals::dh::{DHParams, KeyPair, PublicKey, SECRET_KEY_SIZE};

/// Test that Diffie-Hellman key exchange can correctly produce a shared secret
#[test]
fn challenge_33() {
    let params: DHParams = DHParams::pgen();

    let alice_keypair: KeyPair = KeyPair::keygen(&params, SECRET_KEY_SIZE);
    let bob_keypair: KeyPair = KeyPair::keygen(&params, SECRET_KEY_SIZE);

    let alice_secret: NonZero<U2048> = alice_keypair
        .get_shared_secret(bob_keypair.get_pk())
        .unwrap();
    let bob_secret: NonZero<U2048> = bob_keypair
        .get_shared_secret(alice_keypair.get_pk())
        .unwrap();

    assert_eq!(alice_secret, bob_secret);
}

/// In a parameter injection attack where the man in the middle swaps each of Alice's and Bob's
/// public key with the prime "p", the shared secret is trivially "0", which means the shared
/// secret key will be trivially the hash of "0" under whichever choice of hash function
#[test]
fn challenge_34() {
    let params: DHParams = DHParams::pgen();

    let alice_keypair: KeyPair = KeyPair::keygen(&params, SECRET_KEY_SIZE);
    let bob_keypair: KeyPair = KeyPair::keygen(&params, SECRET_KEY_SIZE);
    let mallory_pk: PublicKey = PublicKey::new(params.get_prime(), params.clone());

    let alice_shared_secret = alice_keypair.get_shared_secret(&mallory_pk);
    let bob_shared_secret = bob_keypair.get_shared_secret(&mallory_pk);
    assert!(alice_shared_secret.is_err());
    assert!(bob_shared_secret.is_err());
}
