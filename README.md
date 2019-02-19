# ripemd128
A pure rust implementation of the RIPEMD-128 cryptographic hash based on [RustCrypto/hashes][3] ripemd160.

# Usage

```rust
use ripemd128::{Ripemd128, Digest};

// create a RIPEMD-128 hasher instance
let mut hasher = Ripemd128::new();

// process input message
hasher.input(b"abc");

// acquire hash digest in the form of GenericArray,
// which in this case is equivalent to [u8; 16]
let result = hasher.result();
// assert_eq!(result[..], hex!("c14a12199c66e4ba84636b0f69144c77"));

```

Also see [RustCrypto/hashes][3] readme.

[1]: https://en.wikipedia.org/wiki/RIPEMD
[2]: https://homes.esat.kuleuven.be/~bosselae/ripemd160.html
[3]: https://github.com/RustCrypto/hashes
