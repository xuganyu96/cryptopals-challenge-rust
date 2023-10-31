//! Diffie-Hellman key exchange
use crypto_bigint::{
    modular::runtime_mod::{DynResidue, DynResidueParams},
    NonZero, Uint,
};
use crypto_primes as primes;

pub mod stream;

/// The parameters of a Diffie-Hellman key exchange include three elements:
/// A cyclic group G with a prime order p, and a generator element of the group
/// If we take G to be integer mod p, then any number greater than 1 can be
/// used as the base "g"
///
/// TODO: Need to implement serialization and deserialization
#[derive(Debug, Clone)]
pub struct DHParams<const LIMBSIZE: usize> {
    /// The order of the group, a prime number
    p: NonZero<Uint<LIMBSIZE>>,

    /// The base element
    g: NonZero<Uint<LIMBSIZE>>,
}

impl<const LIMBSIZE: usize> DHParams<LIMBSIZE> {
    /// Given the ambient prime and the base, return self
    pub fn new(p: NonZero<Uint<{ LIMBSIZE }>>, g: NonZero<Uint<{ LIMBSIZE }>>) -> Self {
        return Self { p, g };
    }

    /// Randomly generate an ambient prime. The base should always be 2 according to RFC3526
    ///
    /// lambda is the bit-length of the ambient prime
    pub fn pgen(lambda: usize) -> Self {
        let p: Uint<{ LIMBSIZE }> = primes::generate_prime(Some(lambda));
        let p = NonZero::new(p).unwrap(); // generate_prime is guaranteed
        let g = NonZero::new(Uint::<{ LIMBSIZE }>::from_u8(2)).unwrap();
        return Self::new(p, g);
    }

    pub fn get_prime(&self) -> NonZero<Uint<{ LIMBSIZE }>> {
        return self.p;
    }

    pub fn get_base(&self) -> NonZero<Uint<{ LIMBSIZE }>> {
        return self.g;
    }
}

type PublicKey<const LIMBSIZE: usize> = NonZero<Uint<LIMBSIZE>>;
type SecretKey<const LIMBSIZE: usize> = NonZero<Uint<LIMBSIZE>>;

/// A single person's key pair consists of a public key and a private key
/// The private key is a random positive integer; the public key is the generator
///
/// TODO: Need to implement serialization and deserialization
#[derive(Debug)]
pub struct KeyPair<const LIMBSIZE: usize> {
    pk: PublicKey<LIMBSIZE>,

    sk: SecretKey<LIMBSIZE>,

    params: DHParams<LIMBSIZE>,
}

impl<const LIMBSIZE: usize> KeyPair<LIMBSIZE> {
    /// Return a read-only reference to the public key
    pub fn get_pk(&self) -> &PublicKey<LIMBSIZE> {
        return &self.pk;
    }

    pub fn get_sk(&self) -> &SecretKey<LIMBSIZE> {
        return &self.sk;
    }

    pub fn get_params(&self) -> &DHParams<LIMBSIZE> {
        return &self.params;
    }

    /// Generate the secret exponent, then compute the public element
    pub fn keygen(params: &DHParams<LIMBSIZE>, lambda: usize) -> Self {
        let sk: SecretKey<LIMBSIZE> = NonZero::new(primes::generate_prime(Some(lambda))).unwrap();

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
    pub fn get_shared_secret(&self, other: &PublicKey<LIMBSIZE>) -> NonZero<Uint<LIMBSIZE>> {
        let modulo = DynResidueParams::new(&self.params.p);
        let secret = DynResidue::new(other, modulo).pow(&self.sk).retrieve();
        return NonZero::new(secret).unwrap();
    }
}
