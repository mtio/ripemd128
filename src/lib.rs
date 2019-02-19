//! An implementation of the [RIPEMD-128][1] cryptographic hash.
//!
//! # Usage
//!
//! ```rust
//! # #[macro_use] extern crate hex_literal;
//! # extern crate ripemd128;
//! # fn main() {
//! use ripemd128::{Ripemd128, Digest};
//!
//! // create a RIPEMD-128 hasher instance
//! let mut hasher = Ripemd128::new();
//!
//! // process input message
//! hasher.input(b"abc");
//!
//! // acquire hash digest in the form of GenericArray,
//! // which in this case is equivalent to [u8; 16]
//! let result = hasher.result();
//! assert_eq!(result[..], hex!("c14a12199c66e4ba84636b0f69144c77"));
//! # }
//! ```
//!
//! Also see [RustCrypto/hashes][3] readme.
//!
//! [1]: https://en.wikipedia.org/wiki/RIPEMD
//! [2]: https://homes.esat.kuleuven.be/~bosselae/ripemd160.html
//! [3]: https://github.com/RustCrypto/hashes
#![no_std]
#![doc(html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo_small.png")]
extern crate block_buffer;
#[macro_use]
extern crate opaque_debug;
#[macro_use]
pub extern crate digest;
#[cfg(feature = "std")]
extern crate std;

use block_buffer::byteorder::{ByteOrder, LE};
use block_buffer::BlockBuffer;
use digest::generic_array::typenum::{U16, U64};
use digest::generic_array::GenericArray;
pub use digest::Digest;
use digest::{BlockInput, FixedOutput, Input, Reset};

mod block;
use block::{process_msg_block, DIGEST_BUF_LEN, H0};

/// Structure representing the state of a Ripemd128 computation
#[derive(Clone)]
pub struct Ripemd128 {
    h: [u32; DIGEST_BUF_LEN],
    len: u64,
    buffer: BlockBuffer<U64>,
}

impl Default for Ripemd128 {
    fn default() -> Self {
        Ripemd128 {
            h: H0,
            len: 0,
            buffer: Default::default(),
        }
    }
}

impl BlockInput for Ripemd128 {
    type BlockSize = U64;
}

impl Input for Ripemd128 {
    fn input<B: AsRef<[u8]>>(&mut self, input: B) {
        let input = input.as_ref();
        // Assumes that input.len() can be converted to u64 without overflow
        self.len += input.len() as u64;
        let h = &mut self.h;
        self.buffer.input(input, |b| process_msg_block(h, b));
    }
}

impl FixedOutput for Ripemd128 {
    type OutputSize = U16;

    fn fixed_result(mut self) -> GenericArray<u8, Self::OutputSize> {
        {
            let h = &mut self.h;
            let l = self.len << 3;
            self.buffer
                .len64_padding::<LE, _>(l, |b| process_msg_block(h, b));
        }

        let mut out = GenericArray::default();
        LE::write_u32_into(&self.h, &mut out[..]);
        out
    }
}

impl Reset for Ripemd128 {
    fn reset(&mut self) {
        self.buffer.reset();
        self.len = 0;
        self.h = H0;
    }
}

impl_opaque_debug!(Ripemd128);
impl_write!(Ripemd128);
