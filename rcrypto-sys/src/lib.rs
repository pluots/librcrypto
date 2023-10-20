#![cfg_attr(not(any(test, feature = "std")), no_std)]

use core::cmp::min;
use core::slice;

use aead::generic_array::typenum::marker_traits::Unsigned;
use aead::AeadInPlace;
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use argon2::password_hash::errors::InvalidValue;
use argon2::password_hash::{errors::Error as PwHashErr, PasswordHash, PasswordVerifier, Salt};
use argon2::PasswordHasher;
use base64ct::{Base64, Base64Unpadded, Base64Url, Base64UrlUnpadded, Encoding};
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
            match res {
                Ok(()) => 0,
                Err(_) => -1,
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

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub enum RcB64Variant {
    RcB64Original,
    RcB64OriginalUnpadded,
    RcB64Url,
    RcB64UrlUnpadded,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub enum RcBase64Result {
    RcB64Ok = 0,
    RcB64InvalidEncoding = -2,
    RcB64InvalidLength = -1,
}

impl From<base64ct::Error> for RcBase64Result {
    fn from(value: base64ct::Error) -> Self {
        match value {
            base64ct::Error::InvalidEncoding => Self::RcB64InvalidEncoding,
            base64ct::Error::InvalidLength => Self::RcB64InvalidLength,
        }
    }
}

/// Constant-time base64 encoding
#[no_mangle]
pub unsafe extern "C" fn rc_base64_encode_ct(
    variant: RcB64Variant,
    bin: *const u8,
    bin_len: usize,
    b64: *mut u8,
    b64_maxlen: usize,
    b64_len: &mut usize,
) -> RcBase64Result {
    let src = unsafe { slice::from_raw_parts(bin, bin_len) };
    let dst = unsafe { slice::from_raw_parts_mut(b64, b64_maxlen) };
    let res = match variant {
        RcB64Variant::RcB64Original => Base64::encode(src, dst),
        RcB64Variant::RcB64OriginalUnpadded => Base64Unpadded::encode(src, dst),
        RcB64Variant::RcB64Url => Base64Url::encode(src, dst),
        RcB64Variant::RcB64UrlUnpadded => Base64UrlUnpadded::encode(src, dst),
    };

    match res {
        Ok(out) => {
            *b64_len = out.len();
            RcBase64Result::RcB64Ok
        }
        Err(_) => RcBase64Result::RcB64InvalidLength,
    }
}

#[no_mangle]
pub unsafe extern "C" fn rc_base64_decode_ct(
    variant: RcB64Variant,
    b64: *const u8,
    b64len: usize,
    bin: *mut u8,
    bin_maxlen: usize,
    bin_len: &mut usize,
) -> RcBase64Result {
    let src = unsafe { slice::from_raw_parts(b64, b64len) };
    let dst = unsafe { slice::from_raw_parts_mut(bin, bin_maxlen) };
    let res = match variant {
        RcB64Variant::RcB64Original => Base64::decode(src, dst),
        RcB64Variant::RcB64OriginalUnpadded => Base64Unpadded::decode(src, dst),
        RcB64Variant::RcB64Url => Base64Url::decode(src, dst),
        RcB64Variant::RcB64UrlUnpadded => Base64UrlUnpadded::decode(src, dst),
    };

    match res {
        Ok(out) => {
            *bin_len = out.len();
            RcBase64Result::RcB64Ok
        }
        Err(e) => e.into(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn rc_base64_encoded_len(variant: RcB64Variant, len: usize) -> usize {
    let tmp = unsafe { slice::from_raw_parts(0xdeadbeef as *const u8, len) };
    match variant {
        RcB64Variant::RcB64Original => Base64::encoded_len(tmp),
        RcB64Variant::RcB64OriginalUnpadded => Base64Unpadded::encoded_len(tmp),
        RcB64Variant::RcB64Url => Base64Url::encoded_len(tmp),
        RcB64Variant::RcB64UrlUnpadded => Base64UrlUnpadded::encoded_len(tmp),
    }
}

#[no_mangle]
pub unsafe extern "C" fn rc_zeroize(ptr: *mut u8, len: usize) {
    use zeroize::Zeroize;
    let buf = unsafe { slice::from_raw_parts_mut(ptr, len) };
    buf.iter_mut().zeroize();
}

/// Maximum length for a password output string. Actual value may be shorter
pub const RC_PWHASH_STRBYTES: usize = 128;
/// Recommended length for salt
pub const RC_PWHASH_SALT_RECOMMENDED_BYTES: usize = Salt::RECOMMENDED_LENGTH;
pub const RC_PWHASH_SALT_MIN_BYTES: usize = Salt::MIN_LENGTH;
pub const RC_PWHASH_SALT_MAX_BYTES: usize = Salt::MAX_LENGTH;

#[repr(C)]
pub enum RcPwhashresult {
    RcPwhashOk = 0,
    RcPwhashPasswordInvalid = 1,
    RcPwhashUnspecifiedError = -1,
    RcPwhashAlgorithm = -2,
    RcPwhashB64Encoding = -3,
    RcPwhashCrypto = -4,
    RcPwhashOutputSize = -5,
    RcPwhashParamNameDuplicated = -6,
    RcPwhashParamNameInvalid = -7,
    RcPwhashParamValueInvalid = -8,
    RcPwhashParamsMaxExceeded = -9,
    RcPwhashPhcStringField = -11,
    RcPwhashPhcStringTrailingData = -12,
    RcPwhashSaltInvalidChar = -13,
    RcPwhashSaltInvalidFormat = -14,
    RcPwhashSaltInvalidMalformed = -15,
    RcPwhashSaltInvalidTooLong = -16,
    RcPwhashSaltInvalidTooShort = -17,
    RcPwhashVersion = -18,
    RcPwhashStringError = -19,
}

impl From<PwHashErr> for RcPwhashresult {
    fn from(value: PwHashErr) -> Self {
        match value {
            PwHashErr::Algorithm => Self::RcPwhashAlgorithm,
            PwHashErr::B64Encoding(_) => Self::RcPwhashB64Encoding,
            PwHashErr::Crypto => Self::RcPwhashCrypto,
            PwHashErr::OutputSize { .. } => Self::RcPwhashOutputSize,
            PwHashErr::ParamNameDuplicated => Self::RcPwhashParamNameDuplicated,
            PwHashErr::ParamNameInvalid => Self::RcPwhashParamNameInvalid,
            PwHashErr::ParamValueInvalid(_) => Self::RcPwhashParamValueInvalid,
            PwHashErr::ParamsMaxExceeded => Self::RcPwhashParamsMaxExceeded,
            PwHashErr::Password => Self::RcPwhashPasswordInvalid,
            PwHashErr::PhcStringField => Self::RcPwhashPhcStringField,
            PwHashErr::PhcStringTrailingData => Self::RcPwhashPhcStringTrailingData,
            PwHashErr::SaltInvalid(InvalidValue::InvalidChar(_)) => Self::RcPwhashSaltInvalidChar,
            PwHashErr::SaltInvalid(InvalidValue::InvalidFormat) => Self::RcPwhashSaltInvalidFormat,
            PwHashErr::SaltInvalid(InvalidValue::Malformed) => Self::RcPwhashSaltInvalidMalformed,
            PwHashErr::SaltInvalid(InvalidValue::TooLong) => Self::RcPwhashSaltInvalidTooLong,
            PwHashErr::SaltInvalid(InvalidValue::TooShort) => Self::RcPwhashSaltInvalidTooShort,
            PwHashErr::Version => Self::RcPwhashVersion,
            _ => Self::RcPwhashUnspecifiedError,
        }
    }
}

/// Hash a password with argon2id v19
#[no_mangle]
pub unsafe extern "C" fn rc_pwhash_argon2(
    pw: *const u8,
    pwlen: usize,
    salt: *const u8, // b64 encoded
    saltlen: usize,
    out: *mut u8,
    out_maxlen: usize,
    outlen: &mut usize,
) -> RcPwhashresult {
    let pw = unsafe { slice::from_raw_parts(pw, pwlen) };
    let salt = unsafe { slice::from_raw_parts(salt, saltlen) };
    let out = unsafe { slice::from_raw_parts_mut(out, out_maxlen) };
    let Ok(salt) = core::str::from_utf8(salt) else {
        return RcPwhashresult::RcPwhashStringError;
    };
    let salt = match Salt::from_b64(salt) {
        Ok(v) => v,
        Err(e) => return dbg!(e).into(),
    };

    let a2 = argon2::Argon2::default();

    let hash = match a2.hash_password(pw, salt) {
        Ok(v) => v,
        Err(e) => return dbg!(e).into(),
    };

    let hash_str = hash.to_string();
    let to_write = min(hash_str.len(), out.len());
    out[..to_write].copy_from_slice(&hash_str.as_bytes()[..to_write]);

    *outlen = hash_str.len();

    RcPwhashresult::RcPwhashOk
}

/// Returns negative if error, +1 if incorrect but everything working, 0 if
/// correct.
#[no_mangle]
pub unsafe extern "C" fn rc_pwhash_argon2_verify(
    pw: *const u8,
    pwlen: usize,
    hash: *const u8,
    hlen: usize,
) -> RcPwhashresult {
    let pw = unsafe { slice::from_raw_parts(pw, pwlen) };
    let hash = unsafe { slice::from_raw_parts(hash, hlen) };
    let Ok(hash) = core::str::from_utf8(hash) else {
        return RcPwhashresult::RcPwhashStringError;
    };
    let parsed_hash = match PasswordHash::new(hash) {
        Ok(v) => v,
        Err(e) => return dbg!(e).into(),
    };
    let res = argon2::Argon2::default().verify_password(pw, &parsed_hash);
    if let Err(e) = res {
        dbg!(e).into()
    } else {
        RcPwhashresult::RcPwhashOk
    }
}
