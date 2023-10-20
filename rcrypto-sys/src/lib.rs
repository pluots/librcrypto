#![cfg_attr(not(any(test, feature = "std")), no_std)]

use core::slice;

use aead::generic_array::typenum::marker_traits::Unsigned;
use aead::AeadInPlace;
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use chacha20poly1305::{ChaCha20Poly1305, XChaCha20Poly1305};

macro_rules! aead_interface {
    ($alg:ty, $id:ident, $name:literal) => {
        paste::paste! {
            aead_interface! {
                $alg,
                $name,
                [<RC_AEAD_ $id:upper _NONCEBYTES>],
                [<RC_AEAD_ $id:upper _KEYBYTES>],
                [<RC_AEAD_ $id:upper _MACBYTES>],
                [<rc_aead_ $id _keygen>],
                [<rc_aead_ $id _noncegen>],
                [<rc_aead_ $id _encrypt>],
                [<rc_aead_ $id _decrypt>],
                [<rc_aead_ $id _encrypt_ad>],
                [<rc_aead_ $id _decrypt_ad>],
                [<tests_ $id>],
            }
        }
    };
    (
        $alg:ty,
        $name:literal,
        $noncebytes:ident,
        $keybytes:ident,
        $macbytes:ident,
        $keygen_fn:ident,
        $noncegen_fn:ident,
        $encrypt_fn:ident,
        $decrypt_fn:ident,
        $encrypt_ad_fn:ident,
        $decrypt_ad_fn:ident,
        $test_mod:ident,
    ) => {
        /// Length of the nonce (initialization vector) for
        #[doc = $name]
        pub const $noncebytes: usize = <$alg as aead::AeadCore>::NonceSize::USIZE;

        /// Length of the key for
        #[doc = $name]
        pub const $keybytes: usize = <$alg as aead::KeySizeUser>::KeySize::USIZE;

        /// Length of the MAC (tag) for
        #[doc = $name]
        pub const $macbytes: usize = <$alg as aead::AeadCore>::TagSize::USIZE;

        /// Generate a nonce suitible for use with the
        #[doc = $name]
        /// algorithm.
        #[doc = concat!("cbindgen: ptrs-as-arrays=[[nonce;", stringify!($noncebytes), "]]")]
        #[no_mangle]
        pub unsafe extern "C" fn $noncegen_fn(nonce: *mut u8) {
            let nonce = unsafe { &mut *nonce.cast::<[u8; $noncebytes]>() };
            *nonce = <$alg as aead::AeadCore>::generate_nonce(aead::OsRng).into();
        }

        /// Generate a key suitible for use with the
        #[doc = $name]
        /// algorithm.
        #[doc = concat!("cbindgen: ptrs-as-arrays=[[key;", stringify!($keybytes), "]]")]
        #[no_mangle]
        pub unsafe extern "C" fn $keygen_fn(key: *mut u8) {
            let key = unsafe { &mut *key.cast::<[u8; $keybytes]>() };
            *key = <$alg as aead::KeyInit>::generate_key(aead::OsRng).into();
        }

        #[doc = concat!(" Encrypt a message using the ", $name, " algorithm.")]
        ///
        /// Returns 0 if successful, -1 otherwise. Parameters:
        ///
        /// - `msg`: an input and output buffer that will be encrypted
        /// - `mlen`: length of the message to be encrypted
        /// - `mac`: an output buffer where the authentecation tag will be written. Must be
        #[doc = concat!("   `", stringify!($macbytes), "` bytes in length.")]
        /// - `nonce`: a number used once, AKA initialization vector. This does not have to be
        ///   confidential and can be stored with the message; however, it may not be reused
        ///   for further encryption. Must be
        #[doc = concat!("   `", stringify!($noncebytes), "` bytes in length.")]
        /// - `key`: the key used to encrypt the message. Must be
        #[doc = concat!("   `", stringify!($keybytes), "` bytes in length.")]
        ///
        /// # SAFETY
        ///
        /// `msg` must point to a valid buffer that is at least `mlen` in length.
        #[doc = concat!("cbindgen: ptrs-as-arrays=[[mac;",
                                                            stringify!($macbytes), "], [nonce;",
                                                            stringify!($noncebytes), "], [key;",
                                                            stringify!($keybytes), "]]"
                                                        )]
        #[no_mangle]
        pub unsafe extern "C" fn $encrypt_fn(
            msg: *mut u8,
            mlen: usize,
            mac: *mut u8,
            nonce: *const u8,
            key: *const u8,
        ) -> i8 {
            $encrypt_ad_fn(msg, mlen, mac, nonce, key, 0xdeadbeef as *const u8, 0)
        }

        #[doc = concat!("cbindgen: ptrs-as-arrays=[[mac;",
                                                            stringify!($macbytes), "], [nonce;",
                                                            stringify!($noncebytes), "], [key;",
                                                            stringify!($keybytes), "]]"
                                                        )]
        #[no_mangle]
        pub unsafe extern "C" fn $encrypt_ad_fn(
            msg: *mut u8,
            mlen: usize,
            mac: *mut u8,
            nonce: *const u8,
            key: *const u8,
            ad: *const u8,
            adlen: usize,
        ) -> i8 {
            // SAFETY: caller guarantees valid data
            let msg = unsafe { slice::from_raw_parts_mut(msg, mlen) };
            let ad = unsafe { slice::from_raw_parts(ad, adlen) };
            let mac = unsafe { &mut *mac.cast::<[u8; $macbytes]>() };
            let nonce = unsafe { &*nonce.cast::<[u8; $noncebytes]>() };
            let key = unsafe { &*key.cast::<[u8; $keybytes]>() };

            let cipher = <$alg as aead::KeyInit>::new_from_slice(key).unwrap();
            let Ok(newmac) = cipher.encrypt_in_place_detached(nonce.as_slice().into(), ad, msg)
            else {
                return -1;
            };

            *mac = newmac.into();
            0
        }

        #[doc = concat!(" Decrypt a message using the ", $name, " algorithm.")]
        ///
        /// Returns 0 if successful, -1 otherwise. Parameters:
        ///
        /// - `msg`: an input and output buffer that will be decrypted
        /// - `mlen`: length of the message to be decrypted
        /// - `mac`: an output buffer where the authentecation tag will be written. Must be
        #[doc = concat!("   `", stringify!($macbytes), "` bytes in length.")]
        /// - `nonce`: a number used once, AKA initialization vector. This does not have to be
        ///   confidential and can be stored with the message; however, it may not be reused
        ///   for further encryption. Must be
        #[doc = concat!("   `", stringify!($noncebytes), "` bytes in length.")]
        /// - `key`: the key used to encrypt the message. Must be
        #[doc = concat!("   `", stringify!($keybytes), "` bytes in length.")]
        ///
        /// # SAFETY
        ///
        /// `msg` must point to a valid buffer that is at least `mlen` in length.
        #[doc = concat!("cbindgen: ptrs-as-arrays=[[mac;",
                                                            stringify!($macbytes), "], [nonce;",
                                                            stringify!($noncebytes), "], [key;",
                                                            stringify!($keybytes), "]]"
                                                        )]
        #[no_mangle]
        pub unsafe extern "C" fn $decrypt_fn(
            msg: *mut u8,
            mlen: usize,
            mac: *const u8,
            nonce: *const u8,
            key: *const u8,
        ) -> i8 {
            $decrypt_ad_fn(msg, mlen, mac, nonce, key, 0xdeadbeef as *const u8, 0)
        }

        #[doc = concat!("cbindgen: ptrs-as-arrays=[[mac;",
                                                            stringify!($macbytes), "], [nonce;",
                                                            stringify!($noncebytes), "], [key;",
                                                            stringify!($keybytes), "]]"
                                                        )]
        #[no_mangle]
        pub unsafe extern "C" fn $decrypt_ad_fn(
            msg: *mut u8,
            mlen: usize,
            mac: *const u8,
            nonce: *const u8,
            key: *const u8,
            ad: *const u8,
            adlen: usize,
        ) -> i8 {
            // SAFETY: caller guarantees valid data
            let msg = unsafe { slice::from_raw_parts_mut(msg, mlen) };
            let ad = unsafe { slice::from_raw_parts(ad, adlen) };
            let mac = unsafe { &*mac.cast::<[u8; $macbytes]>() };
            let nonce = unsafe { &*nonce.cast::<[u8; $noncebytes]>() };
            let key = unsafe { &*key.cast::<[u8; $keybytes]>() };

            let cipher = <$alg as aead::KeyInit>::new_from_slice(key).unwrap();
            let res =
                cipher.decrypt_in_place_detached(nonce.as_slice().into(), ad, msg, mac.into());
            if res.is_err() {
                -1
            } else {
                0
            }
        }

        #[cfg(test)]
        mod $test_mod {
            use super::*;

            #[test]
            fn roundtrip() {
                let mut key = [0u8; $keybytes];
                let mut nonce = [0u8; $noncebytes];
                let mut mac = [0u8; $macbytes];
                let mut msg: [u8; 13] = b"Hello, world!".as_slice().try_into().unwrap();
                let orig_msg = msg.clone();

                unsafe {
                    $noncegen_fn(nonce.as_mut_ptr());
                    $keygen_fn(key.as_mut_ptr());
                    $encrypt_fn(
                        msg.as_mut_ptr(),
                        msg.len(),
                        mac.as_mut_ptr(),
                        nonce.as_ptr(),
                        key.as_ptr(),
                    );

                    assert_ne!(msg, orig_msg);

                    $decrypt_fn(
                        msg.as_mut_ptr(),
                        msg.len(),
                        mac.as_ptr(),
                        nonce.as_ptr(),
                        key.as_ptr(),
                    );

                    assert_eq!(msg, orig_msg);
                }
            }
        }
    };
}

aead_interface!(Aes128Gcm, aes128gcm, "AES128-GCM");
aead_interface!(Aes256Gcm, aes256gcm, "AES256-GCM");
aead_interface!(ChaCha20Poly1305, chacha20poly1305, "ChaCha20-Poly1305");
aead_interface!(XChaCha20Poly1305, xchacha20poly1305, "XChaCha20-Poly1305");
aead_interface!(
    crypto_secretbox::XSalsa20Poly1305,
    "XSalsa20-Poly1305",
    RC_SECRETBOX_KEYBYTES,
    RC_SECRETBOX_NONCEBYTES,
    RC_SECRETBOX_MACBYTES,
    rc_secretbox_noncegen,
    rc_secretbox_keygen,
    rc_secretbox_detached,
    rc_secretbox_open_detached,
    rc_secretbox_detached_ad,
    rc_secretbox_open_detached_ad,
    test_salsa,
);
