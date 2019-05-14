# Sealed

Typed encryption, generic over serde::Serialize and DeserializeOwned.

Why? Cryptography should be easy and safe. This crate aims to make cryptographic protocols
easy to define and iterate upon.

### Example: onion routing

```rust
#[derive(Serialize, Deserialize)]
enum OnionRequest {
    Data(Sealed<Vec<u8>>),
    Proxy(Box<(SocketAddr, Sealed<OnionRequest>)>),
}
```
