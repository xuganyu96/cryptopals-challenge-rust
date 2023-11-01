//! Some of the test might be slow when running in debug mode;
//! use "cargo test --profile release" to speed up prime generations
use crypto_bigint::{NonZero, U2048};
use cryptopals::dh::{DHParams, KeyPair};

#[test]
fn challenge_33() {
    // RFC3526 requires ambient prime to be 2048 bits (256 bytes)
    let params: DHParams = DHParams::pgen(2048);

    let alice_keypair: KeyPair = KeyPair::keygen(&params, 256);
    let bob_keypair: KeyPair = KeyPair::keygen(&params, 256);

    let alice_secret: NonZero<U2048> = alice_keypair.get_shared_secret(bob_keypair.get_pk());
    let bob_secret: NonZero<U2048> = bob_keypair.get_shared_secret(alice_keypair.get_pk());

    assert_eq!(alice_secret, bob_secret);
}
