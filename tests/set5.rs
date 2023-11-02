//! Some of the test might be slow when running in debug mode;
//! use "cargo test --profile release" to speed up prime generations
use crypto_bigint::{CheckedSub, NonZero, U2048};
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

/// When the base is 1, the shared secret is always 1
/// When the base is p, the shared secret is always 0
/// When the base is (p-1), the shared secret is either 1 or -1 (mod p)
#[test]
fn challenge_35() {
    let prime = U2048::from_be_hex(concat!(
        "FFFFFFFF", "FFFFFFFF", "ADF85458", "A2BB4A9A", "AFDC5620", "273D3CF1", "D8B9C583",
        "CE2D3695", "A9E13641", "146433FB", "CC939DCE", "249B3EF9", "7D2FE363", "630C75D8",
        "F681B202", "AEC4617A", "D3DF1ED5", "D5FD6561", "2433F51F", "5F066ED0", "85636555",
        "3DED1AF3", "B557135E", "7F57C935", "984F0C70", "E0E68B77", "E2A689DA", "F3EFE872",
        "1DF158A1", "36ADE735", "30ACCA4F", "483A797A", "BC0AB182", "B324FB61", "D108A94B",
        "B2C8E3FB", "B96ADAB7", "60D7F468", "1D4F42A3", "DE394DF4", "AE56EDE7", "6372BB19",
        "0B07A7C8", "EE0A6D70", "9E02FCE1", "CDF7E2EC", "C03404CD", "28342F61", "9172FE9C",
        "E98583FF", "8E4F1232", "EEF28183", "C3FE3B1B", "4C6FAD73", "3BB5FCBC", "2EC22005",
        "C58EF183", "7D1683B2", "C6F34A26", "C1B2EFFA", "886B4238", "61285C97", "FFFFFFFF",
        "FFFFFFFF",
    ));
    let prime = NonZero::new(prime).unwrap();

    // When base is 1
    let base = NonZero::new(U2048::ONE).unwrap();
    let params: DHParams = DHParams::new(prime, base);
    let alice_keypair = KeyPair::keygen(&params, SECRET_KEY_SIZE);
    let bob_keypair = KeyPair::keygen(&params, SECRET_KEY_SIZE);
    let shared_secret = bob_keypair
        .get_shared_secret(alice_keypair.get_pk())
        .unwrap();
    assert_eq!(shared_secret, NonZero::new(U2048::ONE).unwrap());

    // When base is p, get_shared_secret will panic
    let params: DHParams = DHParams::new(prime, prime);
    let alice_keypair = KeyPair::try_keygen(&params, SECRET_KEY_SIZE);
    assert!(alice_keypair.is_err());

    // When base is p-1
    let base = NonZero::new(prime.checked_sub(&U2048::ONE).unwrap()).unwrap();
    let params: DHParams = DHParams::new(prime, base);
    let alice_keypair = KeyPair::keygen(&params, SECRET_KEY_SIZE);
    let bob_keypair = KeyPair::keygen(&params, SECRET_KEY_SIZE);
    let shared_secret = bob_keypair
        .get_shared_secret(alice_keypair.get_pk())
        .unwrap();
    assert!(shared_secret == NonZero::new(U2048::ONE).unwrap() || shared_secret == base);
}
