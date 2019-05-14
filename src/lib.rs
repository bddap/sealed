//! Typed encryption, generic over serde::Serialize and DeserializeOwned.
//!
//! ```rust
//! # use rust_sodium::crypto::box_::gen_keypair;
//! # use crate::sealed::Sealed;
//! # let (destination_public_key, destination_secret_key) = gen_keypair();
//! # let source_secret_key = gen_keypair().1;
//! let message = Sealed::seal(
//!     &destination_public_key,
//!     &source_secret_key,
//!     &(String::from("to encrypt"), 9u8, 0.5f32),
//! ).unwrap();
//!
//! assert_eq!(
//!     Sealed::open(message, &destination_secret_key)
//!         .unwrap()
//!         .deserialize()
//!         .unwrap(),
//!     (String::from("to encrypt"), 9u8, 0.5f32)
//! );
//! ```
//!
//! The following example shows the evolution a protocol.
//!
//! ```rust
//! # use crate::sealed::Sealed;
//! # #[derive(Serialize, Deserialize)]
//! # struct Time;
//! # use std::net::SocketAddr;
//! # use serde::{Serialize, Deserialize};
//! # use pow::Pow;
//! # {
//! // Packet type is declared
//! type Packet = Sealed<(String, u32, f32)>;
//! # }
//!
//! # {
//! // A field is added to the packet
//! type Packet = Sealed<(String, u32, f32, f64)>;
//! # }
//!
//! # {
//! // A field that was previously encrypted is now sent as plaintext
//! type Packet = (Sealed<(String, u32, f64)>, f32);
//! # }
//!
//! // Type is refactored for readability
//! #[derive(Serialize, Deserialize)]
//! struct ChatMessage {
//!     message: String,
//!     message_id: u32,
//!     distance: f64,
//! }
//! # {
//! type Packet = (Sealed<ChatMessage>, f32);
//! # }
//!
//! // Protocol is upgraded to support batch messages
//! type Packet = (Sealed<Vec<ChatMessage>>, f32);
//!
//! # {
//! // Plaintext field gets a name
//! #[derive(Serialize, Deserialize)]
//! struct Packet {
//!     messages: Sealed<Vec<ChatMessage>>,
//!     temperature: f32,
//! }
//! # }
//!
//! # {
//! // A relay server is implemented to work around NAT
//! struct RelayRequest {
//!     destination: SocketAddr,
//!     payload: Packet,
//! }
//! # }
//!
//! // DOS protection is added
//! struct RelayRequest {
//!     proof_of_work: Pow<(SocketAddr, Packet, Time)>,
//!     time: Time,
//!     destination: SocketAddr,
//!     payload: Packet,
//! }
//!
//! # {
//! // Relay messages are encrypted
//! type EncryptedRelayRequest = Sealed<RelayRequest>;
//! # }
//! ```
//!
//! ## A sealed value is:
//!
//! - Encrypted. Only the source or destination private key can ascertain the contents.
//! - Authenticated. Messages are unforgeable except using the source or the destination private key.
//! - Serializable and Deserializable.
//!
//! This crate does not provide forward secrecy, but forward secret protocols can be implemented
//! using this crate.
//!
//! ```rust
//! # use crate::sealed::Sealed;
//! # use rust_sodium::crypto::box_::gen_keypair;
//! # let destination_pk = gen_keypair().0;
//! # let source_sk = gen_keypair().1;
//! // An example providing half forward secrecy (Destination can decrypt old messages, but source
//! // cannot.)
//!
//! // Source uses an Ephemeral key to encrypt the outer packet, that way the sources private key
//! // can be revealed later without revealing message contents.
//! type Packet = Sealed<Sealed<String>>;
//!
//! let message: Packet = Sealed::seal(
//!     &destination_pk,
//!     &gen_keypair().1,
//!     &Sealed::seal(&destination_pk, &source_sk, &String::from("Hey there.")).unwrap()
//! ).unwrap();
//! ```
//!
//! This crate makes no assumptions about underlying transport. Encrypted data can be sent over UDP, saved to a
//! file, slipped into a fortune cookie, encoded as a qr code and tattooed on somebodies back, or simply
//! printed to stdout.
//!
//! ```rust
//! # use rust_sodium::crypto::box_::gen_keypair;
//! # use crate::sealed::Sealed;
//! # let destination_pk = gen_keypair().0;
//! # let source_sk = gen_keypair().1;
//! // Write and encrypted json object to stdout
//! use serde_json::{self, json};
//! use std::io::stdout;
//!
//! let secret = json![{
//!     "name": "Bob",
//!     "age": 300
//! }];
//! let enc = Sealed::seal(&destination_pk, &source_sk, &secret).unwrap();
//! bincode::config().big_endian().serialize_into(&mut stdout(), &enc).unwrap();
//! ```

mod sealed;

pub use crate::sealed::Sealed;
