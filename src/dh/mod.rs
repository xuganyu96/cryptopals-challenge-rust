//! Diffie-Hellman key exchange
use crypto_bigint::{
    modular::runtime_mod::{DynResidue, DynResidueParams},
    Encoding, NonZero, U2048,
};
use crypto_primes as primes;
use std::error::Error;

type Result<T> = core::result::Result<T, Box<dyn Error>>;

pub mod stream;

/// Recommended num of bits for secret key
pub const SECRET_KEY_SIZE: usize = 256usize;

/// Recommended choice of prime according to:
/// https://www.rfc-editor.org/rfc/rfc7919.html#appendix-A.1
const DH2048_PRIME_HEX: &str = concat!(
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
);

/// Recommended choice of base for 2048-bit DH
const DH2048_BASE: U2048 = U2048::from_u8(2);

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
    pub fn pgen() -> Self {
        let p: U2048 = U2048::from_be_hex(DH2048_PRIME_HEX);
        let p = NonZero::new(p).unwrap(); // generate_prime is guaranteed
        let g = NonZero::new(DH2048_BASE).unwrap();
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

    /// Directly instantiate an instance of a public key
    pub fn new(pub_exp: NonZero<U2048>, params: DHParams) -> Self {
        return Self(pub_exp, params);
    }

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
        let base =
            U2048::from_be_slice(bytes.get((2 * U2048::BYTES)..(3 * U2048::BYTES)).unwrap());
        let params = DHParams::new(NonZero::new(prime).unwrap(), NonZero::new(base).unwrap());
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

    /// A safer keygen that does not panic?
    pub fn try_keygen(params: &DHParams, lambda: usize) -> Result<Self> {
        let sk: SecretKey = NonZero::new(primes::generate_prime(Some(lambda))).unwrap();

        let modulo = DynResidueParams::new(&params.p);
        let pub_exp = DynResidue::new(&params.g, modulo).pow(&sk).retrieve();
        if pub_exp == U2048::ZERO {
            return Err("Bad parameters".into());
        }
        let pub_exp = NonZero::new(pub_exp).unwrap();
        return Ok(Self {
            pk: PublicKey(pub_exp, params.clone()),
            sk,
        });
    }

    /// Compute the shared secret from the other person's public key
    pub fn get_shared_secret(&self, other: &PublicKey) -> Result<NonZero<U2048>> {
        let modulo = DynResidueParams::new(&self.pk.get_prime());
        let secret = DynResidue::new(&other.get_public_exp(), modulo)
            .pow(&self.sk)
            .retrieve();
        let secret = NonZero::new(secret);
        if secret.is_some().into() {
            return Ok(secret.unwrap());
        }
        return Err("Shared secret is zero".into());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_correctness() {
        // RFC3526 requires ambient prime to be 2048 bits (256 bytes)
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

    #[test]
    fn test_serde() {
        let params: DHParams = DHParams::pgen();
        let keypair: KeyPair = KeyPair::keygen(&params, SECRET_KEY_SIZE);

        let public_transmit = keypair.get_pk().to_be_bytes();

        assert_eq!(PublicKey::from_be_bytes(public_transmit), *keypair.get_pk());
    }
}
