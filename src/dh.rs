//! Diffie-Hellman key exchange
use std::error::Error;
use crypto_bigint::{
    Encoding,
    modular::runtime_mod::{DynResidue, DynResidueParams},
    NonZero, Uint, 
};
use crypto_primes as primes;

pub mod stream;

type Result<T> = core::result::Result<T, Box<dyn Error>>;

/// The parameters of a Diffie-Hellman key exchange include three elements:
/// A cyclic group G with a prime order p, and a generator element of the group
/// If we take G to be integer mod p, then any number greater than 1 can be
/// used as the base "g"
///
/// TODO: Need to implement serialization and deserialization
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct DHParams<const LIMBS: usize> {
    /// The order of the group, a prime number
    p: NonZero<Uint<LIMBS>>,

    /// The base element
    g: NonZero<Uint<LIMBS>>,
}

impl<const LIMBS: usize> DHParams<LIMBS> {
    /// Given the ambient prime and the base, return self
    pub fn new(p: NonZero<Uint<{ LIMBS }>>, g: NonZero<Uint<{ LIMBS }>>) -> Self {
        return Self { p, g };
    }

    /// Randomly generate an ambient prime. The base should always be 2 according to RFC3526
    ///
    /// lambda is the bit-length of the ambient prime
    pub fn pgen(lambda: usize) -> Self {
        let p: Uint<{ LIMBS }> = primes::generate_prime(Some(lambda));
        let p = NonZero::new(p).unwrap(); // generate_prime is guaranteed
        let g = NonZero::new(Uint::<{ LIMBS }>::from_u8(2)).unwrap();
        return Self::new(p, g);
    }

    pub fn get_prime(&self) -> NonZero<Uint<{ LIMBS }>> {
        return self.p;
    }

    pub fn get_base(&self) -> NonZero<Uint<{ LIMBS }>> {
        return self.g;
    }
}

type PublicKey<const LIMBS: usize> = NonZero<Uint<LIMBS>>;
type SecretKey<const LIMBS: usize> = NonZero<Uint<LIMBS>>;

/// A single person's key pair consists of a public key and a private key
/// The private key is a random positive integer; the public key is the generator
///
/// TODO: Need to implement serialization and deserialization
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct KeyPair<const LIMBS: usize> {
    pk: PublicKey<LIMBS>,

    sk: SecretKey<LIMBS>,

    params: DHParams<LIMBS>,
}

impl<const LIMBS: usize> KeyPair<LIMBS> {
    /// Return a read-only reference to the public key
    pub fn get_pk(&self) -> &PublicKey<LIMBS> {
        return &self.pk;
    }

    pub fn get_sk(&self) -> &SecretKey<LIMBS> {
        return &self.sk;
    }

    pub fn get_params(&self) -> &DHParams<LIMBS> {
        return &self.params;
    }

    /// Generate the secret exponent, then compute the public element
    pub fn keygen(params: &DHParams<LIMBS>, lambda: usize) -> Self {
        let sk: SecretKey<LIMBS> = NonZero::new(primes::generate_prime(Some(lambda))).unwrap();

        let modulo = DynResidueParams::new(&params.p);
        let pk = DynResidue::new(&params.g, modulo).pow(&sk).retrieve();
        let pk = NonZero::new(pk).unwrap();
        return Self {
            pk,
            sk,
            params: params.clone(),
        };
    }

    /// Compute the shared secret from the other person's public key
    pub fn get_shared_secret(&self, other: &PublicKey<LIMBS>) -> NonZero<Uint<LIMBS>> {
        let modulo = DynResidueParams::new(&self.params.p);
        let secret = DynResidue::new(other, modulo).pow(&self.sk).retrieve();
        return NonZero::new(secret).unwrap();
    }

    /// Serialize to bytes. The size of each element is known at compile time: pk and sk each takes
    /// 8 * LIMBS bytes; params contains two fields, each being 8 * LIMBS bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];

        self.pk.to_limbs().iter()
            .for_each(|limb| {
                bytes.extend_from_slice(&limb.to_be_bytes());
            });
        self.sk.to_limbs().iter()
            .for_each(|limb| {
                bytes.extend_from_slice(&limb.to_be_bytes());
            });
        self.params.get_prime().to_limbs().iter()
            .for_each(|limb| {
                bytes.extend_from_slice(&limb.to_be_bytes());
            });
        self.params.get_base().to_limbs().iter()
            .for_each(|limb| {
                bytes.extend_from_slice(&limb.to_be_bytes());
            });
        
        return bytes;
    }

    /// Deserialize from bytes. The size of each element is exactly (8 * LIMBS) bytes.
    #[allow(unused_variables)]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != (4 * 8 * LIMBS) {
            return Err("Incorrect length".into());
        }
        let pkbytes = bytes.get(0..(8 * LIMBS)).unwrap();
        let skbytes = bytes.get((8 * LIMBS)..(16 * LIMBS)).unwrap();
        let primebytes = bytes.get((16 * LIMBS)..(24 * LIMBS)).unwrap();
        let basebytes = bytes.get((24 * LIMBS)..(32 * LIMBS)).unwrap();

        let pk = NonZero::new(Uint::<LIMBS>::from_be_slice(&pkbytes)).unwrap();
        let sk = NonZero::new(Uint::<LIMBS>::from_be_slice(&skbytes)).unwrap();
        let prime = NonZero::new(Uint::<LIMBS>::from_be_slice(&primebytes)).unwrap();
        let base = NonZero::new(Uint::<LIMBS>::from_be_slice(&basebytes)).unwrap();

        return Ok(Self {
            pk, sk, params: DHParams{ p: prime, g: base }
        });
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    const LIMBS: usize = 32;

    #[test]
    fn test_correctness() {
        // RFC3526 requires ambient prime to be 2048 bits (256 bytes)
        let params: DHParams<LIMBS> = DHParams::pgen(2048);

        let alice_keypair: KeyPair<LIMBS> = KeyPair::keygen(&params, 256);
        let bob_keypair: KeyPair<LIMBS> = KeyPair::keygen(&params, 256);

        let alice_secret: NonZero<Uint<LIMBS>> = alice_keypair.get_shared_secret(bob_keypair.get_pk());
        let bob_secret: NonZero<Uint<LIMBS>> = bob_keypair.get_shared_secret(alice_keypair.get_pk());

        assert_eq!(alice_secret, bob_secret);
    }

    #[test]
    fn test_serde() {
        let params: DHParams<LIMBS> = DHParams::pgen(2048);
        let keypair: KeyPair<LIMBS> = KeyPair::keygen(&params, 256);
        
        let serial = keypair.to_bytes();
        assert_eq!(KeyPair::<LIMBS>::from_bytes(&serial).unwrap(), keypair);
    }
}
