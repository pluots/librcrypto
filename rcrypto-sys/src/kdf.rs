//! Key derivation functions

use core::cmp::min;
use core::slice;

use argon2::password_hash::errors::InvalidValue;
use argon2::password_hash::{errors::Error as PwHashErr, PasswordHash, PasswordVerifier, Salt};
use argon2::PasswordHasher;

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
