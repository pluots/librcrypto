#![cfg_attr(not(any(test, feature = "std")), no_std)]
#![allow(rustdoc::broken_intra_doc_links)] // rustdoc thinks bindgen annotations are links...

pub mod aeads;
pub mod b64;
pub mod kdf;
pub mod zeroize;
