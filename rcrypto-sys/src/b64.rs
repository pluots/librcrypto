//! Base64 operations

use core::slice;

use base64ct::{Base64, Base64Unpadded, Base64Url, Base64UrlUnpadded, Encoding};

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

/// Constant-time base64 encoding (bin -> b64)
///
/// - `variant`: the encoding scheme to use
/// - `bin`: pointer to date to be encoded
/// - `bin_len`: length of data to be encoded, in bytes
/// - `b64`: destination of base64-encoded data
/// - `b64_maxlen`: the length of buffer `b64`. If this is not long enough for the encoded
///   data, the output will be truncated.
/// - `b64_len`: length of the encoded data after being written
///
/// # Safety
///
/// All buffers must be valid for their associated lengths (`bin` -> `bin_len`,
/// `b64` -> `b64_maxlen`).
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

/// Constant-time base64 decoding (b64 -> bin)
///
/// - `variant`: the encoding scheme to use
/// - `b64`: pointer to date to be decoded
/// - `b64_len`: length of data to be decoded, in bytes
/// - `bin`: destination of binary data
/// - `bin_maxlen`: the length of buffer `bin`. If this is not long enough for the encoded
///   data, the output will be truncated.
/// - `b64_len`: length of the encoded data after being written
///
/// # Safety
///
/// All buffers must be valid for their associated lengths (`bin` -> `bin_len`,
/// `b64` -> `b64_maxlen`).
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

/// Determine the length required to encode data with a specific base64 variant.
#[no_mangle]
pub extern "C" fn rc_base64_encoded_len(variant: RcB64Variant, len: usize) -> usize {
    // SAFETY: technically not safe, but `encoded_length` only uses the length parameter
    let tmp = unsafe { slice::from_raw_parts(0xdeadbeef as *const u8, len) };
    match variant {
        RcB64Variant::RcB64Original => Base64::encoded_len(tmp),
        RcB64Variant::RcB64OriginalUnpadded => Base64Unpadded::encoded_len(tmp),
        RcB64Variant::RcB64Url => Base64Url::encoded_len(tmp),
        RcB64Variant::RcB64UrlUnpadded => Base64UrlUnpadded::encoded_len(tmp),
    }
}
