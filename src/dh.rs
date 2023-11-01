//! Diffie-Hellman key exchange
use crypto_bigint::{
    modular::runtime_mod::{DynResidue, DynResidueParams},
    Encoding, NonZero, U2048,
};
use crypto_primes as primes;
use std::error::Error;

type Result<T> = core::result::Result<T, Box<dyn Error>>;

/// Recommended num of bits for modulus
pub const MODULUS_SIZE: usize = 2048usize;

/// Recommended num of bits for secret key
pub const SECRET_KEY_SIZE: usize = 256usize;

/// The parameters of a Diffie-Hellman key exchange include three elements:
/// A cyclic group G with a prime order p, and a generator element of the group
/// If we take G to be integer mod p, then any number greater than 1 can be
/// used as the base "g"
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct DHParams {
    /// The order of the group, a prime number
    p: NonZero<U2048>,

    /// The base element
    g: NonZero<U2048>,
}

impl DHParams {
    /// Given the ambient prime and the base, return self
    pub fn new(p: NonZero<U2048>, g: NonZero<U2048>) -> Self {
        return Self { p, g };
    }

    /// Randomly generate an ambient prime. The base should always be 2 according to RFC3526
    ///
    /// lambda is the bit-length of the ambient prime
    pub fn pgen(lambda: usize) -> Self {
        let p: U2048 = primes::generate_safe_prime(Some(lambda));
        let p = NonZero::new(p).unwrap(); // generate_prime is guaranteed
        let g = NonZero::new(U2048::from_u8(2)).unwrap();
        return Self::new(p, g);
    }

    pub fn get_prime(&self) -> NonZero<U2048> {
        return self.p;
    }

    pub fn get_base(&self) -> NonZero<U2048> {
        return self.g;
    }
}

/// The public key includes both the public exponent and the parameters
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct PublicKey(NonZero<U2048>, DHParams);

impl PublicKey {
    pub const BYTES: usize = U2048::BYTES * 3;

    pub fn get_public_exp(&self) -> NonZero<U2048> {
        return self.0;
    }

    pub fn get_params(&self) -> DHParams {
        return self.1;
    }

    pub fn get_prime(&self) -> NonZero<U2048> {
        return self.1.p;
    }

    pub fn get_base(&self) -> NonZero<U2048> {
        return self.1.g;
    }

    pub fn to_be_bytes(&self) -> [u8; Self::BYTES] {
        let mut bytes = [0u8; U2048::BYTES * 3];

        bytes
            .get_mut(0..U2048::BYTES)
            .unwrap()
            .copy_from_slice(&self.get_public_exp().to_be_bytes());
        bytes
            .get_mut(U2048::BYTES..(2 * U2048::BYTES))
            .unwrap()
            .copy_from_slice(&self.get_prime().to_be_bytes());
        bytes
            .get_mut((2 * U2048::BYTES)..(3 * U2048::BYTES))
            .unwrap()
            .copy_from_slice(&self.get_base().to_be_bytes());

        return bytes;
    }

    pub fn from_be_bytes(bytes: [u8; Self::BYTES]) -> Self {
        let public_exp = U2048::from_be_slice(bytes.get(0..U2048::BYTES).unwrap());
        let prime = U2048::from_be_slice(bytes.get(U2048::BYTES..(2 * U2048::BYTES)).unwrap());
        let base = U2048::from_be_slice(bytes.get((2 * U2048::BYTES)..(3 * U2048::BYTES)).unwrap());
        let params = DHParams::new(
            NonZero::new(prime).unwrap(), 
            NonZero::new(base).unwrap(),
        );
        return Self(NonZero::new(public_exp).unwrap(), params);
    }

    pub fn from_be_slice(slice: &[u8]) -> Result<Self> {
        if slice.len() != U2048::BYTES * 3 {
            return Err("Invalid length".into());
        }
        let mut bytes = [0u8; U2048::BYTES * 3];
        bytes.clone_from_slice(slice);
        return Ok(Self::from_be_bytes(bytes));
    }
}

/// The secret key is exactly a secret exponent
type SecretKey = NonZero<U2048>;

/// A single person's key pair consists of a public key and a private key
/// The private key is a random positive integer; the public key is the generator
///
/// TODO: Need to implement serialization and deserialization
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct KeyPair {
    pk: PublicKey,

    sk: SecretKey,
}

impl KeyPair {
    /// Return a read-only reference to the public key
    pub fn get_pk(&self) -> &PublicKey {
        return &self.pk;
    }

    /// Return a read-only reference to the secret exponent
    pub fn get_sk(&self) -> &SecretKey {
        return &self.sk;
    }

    /// Generate the secret exponent, then compute the public element
    pub fn keygen(params: &DHParams, lambda: usize) -> Self {
        let sk: SecretKey = NonZero::new(primes::generate_prime(Some(lambda))).unwrap();

        let modulo = DynResidueParams::new(&params.p);
        let pub_exp = DynResidue::new(&params.g, modulo).pow(&sk).retrieve();
        let pub_exp = NonZero::new(pub_exp).unwrap();
        return Self {
            pk: PublicKey(pub_exp, params.clone()),
            sk,
        };
    }

    /// Compute the shared secret from the other person's public key
    pub fn get_shared_secret(&self, other: &PublicKey) -> NonZero<U2048> {
        let modulo = DynResidueParams::new(&self.pk.get_prime());
        let secret = DynResidue::new(&other.get_public_exp(), modulo)
            .pow(&self.sk)
            .retrieve();
        return NonZero::new(secret).unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_correctness() {
        // RFC3526 requires ambient prime to be 2048 bits (256 bytes)
        let params: DHParams = DHParams::pgen(MODULUS_SIZE);

        let alice_keypair: KeyPair = KeyPair::keygen(&params, SECRET_KEY_SIZE);
        let bob_keypair: KeyPair = KeyPair::keygen(&params, SECRET_KEY_SIZE);

        let alice_secret: NonZero<U2048> = alice_keypair.get_shared_secret(bob_keypair.get_pk());
        let bob_secret: NonZero<U2048> = bob_keypair.get_shared_secret(alice_keypair.get_pk());

        assert_eq!(alice_secret, bob_secret);
    }

    #[test]
    fn test_serde() {
        let params: DHParams = DHParams::pgen(MODULUS_SIZE);
        let keypair: KeyPair = KeyPair::keygen(&params, SECRET_KEY_SIZE);

        let public_transmit = keypair.get_pk().to_be_bytes();

        assert_eq!(PublicKey::from_be_bytes(public_transmit), *keypair.get_pk());
    }
}
