use core::marker::PhantomData;
use rust_sodium::crypto::box_::{
    gen_nonce, open_detached_precomputed, precompute, seal_detached_precomputed, Nonce,
    PrecomputedKey, PublicKey, SecretKey, Tag,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
pub struct Sealed<T: Serialize + DeserializeOwned> {
    /// Public key of sender.
    source_pk: PublicKey,
    nonce: Nonce,
    /// Message authentication code.
    mac: Tag,
    /// A serialized, then encrypted T.
    cyphertext: Vec<u8>,
    _spook: PhantomData<T>,
}

/// ```rust
/// # use crate::sealed::Sealed;
/// # use rust_sodium::crypto::box_::gen_keypair;
/// let sender_sk = gen_keypair().1;
/// let (receiver_pk, receiver_sk) = gen_keypair();
/// let cyphertext = Sealed::seal(
///     &receiver_pk,
///     &sender_sk,
///     &("Secet Number:".to_string(), 9u8)
/// ).unwrap();
/// let opened = cyphertext.open(&receiver_sk).unwrap();
/// let deserialized = opened.deserialize().unwrap();
/// ```
impl<T: Serialize + DeserializeOwned> Sealed<T> {
    pub fn open(self, destination_sk: &SecretKey) -> Option<Opened<T>> {
        let shared_secret = precompute(&self.source_pk, destination_sk);
        self.open_precomputed(shared_secret)
    }

    pub fn open_precomputed(self, shared_secret: PrecomputedKey) -> Option<Opened<T>> {
        let Sealed {
            source_pk,
            nonce,
            mac,
            mut cyphertext,
            _spook,
        } = self;
        let shared_send_secret = send_sk(shared_secret, &source_pk);
        open_detached_precomputed(&mut cyphertext, &mac, &nonce, &shared_send_secret).ok()?;
        Some(Opened {
            plaintext: cyphertext,
            _spook: PhantomData,
        })
    }

    pub fn seal(
        destination_pk: &PublicKey,
        source_sk: &SecretKey,
        plaintext: &T,
    ) -> bincode::Result<Sealed<T>> {
        let shared_secret = precompute(&destination_pk, &source_sk);
        let source_pk = source_sk.public_key();
        Sealed::seal_precomputed(source_pk, shared_secret, plaintext)
    }

    pub fn seal_precomputed(
        source_pk: PublicKey,
        shared_secret: PrecomputedKey,
        plaintext: &T,
    ) -> bincode::Result<Sealed<T>> {
        let mut plaintext: Vec<u8> = serialize_be(plaintext)?;
        let shared_send_secret = send_sk(shared_secret, &source_pk);
        let nonce = gen_nonce();
        let mac = seal_detached_precomputed(&mut plaintext, &nonce, &shared_send_secret);
        Ok(Sealed {
            source_pk,
            nonce,
            mac,
            cyphertext: plaintext,
            _spook: PhantomData,
        })
    }

    /// get unverified Public key of sender
    pub fn source_pk(&self) -> &PublicKey {
        &self.source_pk
    }
}

/// A decrypted series of bytes. Ready to be deserialized to a T.
#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
pub struct Opened<T: DeserializeOwned> {
    plaintext: Vec<u8>,
    _spook: PhantomData<T>,
}

impl<T: DeserializeOwned> Opened<T> {
    pub fn deserialize(&self) -> bincode::Result<T> {
        deserialize_be::<T>(&self.plaintext)
    }
}

impl<T: DeserializeOwned> Drop for Opened<T> {
    fn drop(&mut self) {
        // clear plaintext from memory
        for b in self.plaintext.iter_mut() {
            *b = 0;
        }
    }
}

/// calculate the key to be used when sending from source_pk
fn send_sk(shared_secret: PrecomputedKey, source_pk: &PublicKey) -> PrecomputedKey {
    // Needs review by a cryptologist. Is xor safe to use here?
    PrecomputedKey(xor_bytes(shared_secret.0, &source_pk.0))
}

fn xor_bytes(mut a: [u8; 32], b: &[u8; 32]) -> [u8; 32] {
    for (s, p) in a.iter_mut().zip(b.iter()) {
        *s ^= p;
    }
    a
}

fn deserialize_be<T: DeserializeOwned>(bs: &[u8]) -> bincode::Result<T> {
    bincode_cfg_be().deserialize(bs)
}

fn serialize_be<T: Serialize>(t: &T) -> bincode::Result<Vec<u8>> {
    bincode_cfg_be().serialize(t)
}

fn bincode_cfg_be() -> bincode::Config {
    let mut cfg = bincode::config();
    cfg.big_endian();
    cfg
}

#[cfg(test)]
mod tests {
    #[test]
    fn onion() {
        // This is more of a hidden doctest as it does not do anything ATM
        use crate::sealed::Sealed;
        use serde::{Deserialize, Serialize};
        use std::net::SocketAddr;
        #[derive(Serialize, Deserialize)]
        enum OnionRequest {
            Data(Sealed<Vec<u8>>),
            Proxy(Box<(SocketAddr, Sealed<OnionRequest>)>),
        }
    }
}
