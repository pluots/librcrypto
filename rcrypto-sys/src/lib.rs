#![cfg_attr(not(any(test, feature = "std")), no_std)]
#![allow(rustdoc::broken_intra_doc_links)] // rustdoc thinks bindgen annotations are links...

pub mod aeads;
pub mod b64;
pub mod kdf;
pub mod zeroize;

/// Version in form `0x00MMmmpp` where `MM` is major, `mm` is minor, and `pp` is patch
#[no_mangle]
pub static RC_VERSION: u32 = make_version();

const fn make_version() -> u32 {
    /// Quick const string parser, since the builtins aren't const
    const fn const_atoi(s: &str) -> u32 {
        let mut i = s.len();
        let mut tmp = 0;
        loop {
            i -= 1;
            // ascii offset and scale
            tmp += ((s.as_bytes()[i] - 48) as u32) * (10u32.pow(i as u32));

            if i == 0 {
                break;
            }
        }
        tmp
    }

    let major = const_atoi(env!("CARGO_PKG_VERSION_MAJOR"));
    let minor = const_atoi(env!("CARGO_PKG_VERSION_MINOR"));
    let patch = const_atoi(env!("CARGO_PKG_VERSION_PATCH"));

    assert!(major < 0xff);
    assert!(minor < 0xff);
    assert!(patch < 0xff);

    (major << 4) | (minor << 2) | patch
}
