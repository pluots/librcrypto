#![no_std]
use core::mem::MaybeUninit;
use core::{ptr, slice};

use aead::generic_array::typenum::marker_traits::Unsigned;
use aead::{AeadCore, AeadInPlace, KeyInit, KeySizeUser, OsRng};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use chacha20poly1305::ChaCha20Poly1305;

/// We need to do lots of things somewhat generically but
macro_rules! for_each_alg {
    ($value:expr, $expr:expr) => {
        match $value {
            RcAeadAlgorithm::Aes256Gcm => {
                type AlgTy = aes_gcm::Aes256Gcm;
                $expr
            }
            RcAeadAlgorithm::Aes128Gcm => {
                type AlgTy = aes_gcm::Aes128Gcm;
                $expr
            }
            RcAeadAlgorithm::ChaCha20Poly1305 => {
                type AlgTy = chacha20poly1305::ChaCha20Poly1305;
                $expr
            }
        }
    };
}

/// Same as above but for our context type
macro_rules! for_each_ctx {
    ($value:expr, $expr:expr, $default:expr) => {
        match $value {
            AeadCtxInner::Aes256Gcm(ref cipher) => {
                type AlgTy = aes_gcm::Aes256Gcm;
                $expr(cipher)
            }
            AeadCtxInner::Aes128Gcm(ref cipher) => {
                type AlgTy = aes_gcm::Aes128Gcm;
                $expr(cipher)
            }
            AeadCtxInner::ChaCha20Poly1305(ref cipher) => {
                type AlgTy = chacha20poly1305::ChaCha20Poly1305;
                $expr(cipher)
            }
            AeadCtxInner::None => $default,
        }
    };
}

#[repr(C)]
pub enum RcResult {
    Ok = 0,
    InvalidKeyLength,
    InvalidNonceLength,
    InvalidDataLength,
    InvalidTagLength,
    InvalidState,
    CryptError,
}

/// An algorithm
#[repr(C)]
#[derive(Clone, Copy)]
pub enum RcAeadAlgorithm {
    Aes256Gcm,
    Aes128Gcm,
    ChaCha20Poly1305,
}

impl RcAeadAlgorithm {
    /// Generate a key and write it to `*dst`. Sets `*dlen` to the number of bytes written.
    ///
    /// If `*dst` is not large enough, `*dlen` will be set to the number of expected bytes.
    ///
    /// # Safety
    ///
    /// `dst` must point to a buffer that is valid for at least `*dlen`
    pub unsafe extern "C" fn rc_aead_generate_key(
        self,
        dst: *mut u8,
        dlen: &mut usize,
    ) -> RcResult {
        for_each_alg! {
            self,
            copy_buf_result(AlgTy::generate_key(OsRng).as_slice(), dst, dlen)
        }
    }

    /// Generate a nonce (IV) and write it to `*dst`. Sets `*dlen` to the number of bytes written.
    ///
    /// If `*dst` is not large enough, `*dlen` will be set to the number of expected bytes.
    ///
    /// # Safety
    ///
    /// `dst` must point to a buffer that is valid for at least `*dlen`
    pub unsafe extern "C" fn rc_aead_generate_nonce(
        self,
        dst: *mut u8,
        dlen: &mut usize,
    ) -> RcResult {
        for_each_alg! {
            self,
            copy_buf_result(AlgTy::generate_nonce(OsRng).as_slice(), dst, dlen)
        }
    }

    /// Give the key size for this algorithm
    pub extern "C" fn rc_aead_key_size(self) -> usize {
        for_each_alg!(self, AlgTy::key_size())
    }

    /// Give the nonce (initialization vector) size for this algorithm
    pub extern "C" fn rc_aead_nonce_size(self) -> usize {
        for_each_alg!(self, <AlgTy as AeadCore>::NonceSize::USIZE)
    }

    /// Give the tag size, i.e. length of additional data
    pub extern "C" fn rc_aead_tag_size(self) -> usize {
        for_each_alg!(self, <AlgTy as AeadCore>::TagSize::USIZE)
    }
}

/// Context that is held among encryption and decryption calls
pub struct RcAeadCtx {
    ctx: AeadCtxInner,
}

enum AeadCtxInner {
    None,
    Aes256Gcm(Aes256Gcm),
    Aes128Gcm(Aes128Gcm),
    ChaCha20Poly1305(ChaCha20Poly1305),
}

impl RcAeadCtx {
    pub unsafe extern "C" fn rc_aead_init(
        this: &mut MaybeUninit<Self>,
        alg: RcAeadAlgorithm,
        key: *const u8,
        klen: usize,
    ) -> RcResult {
        let key = unsafe { slice::from_raw_parts(key, klen) };
        let ctx = for_each_alg!(alg, {
            let alg = AlgTy::new_from_slice(key);
            if alg.is_err() {
                return RcResult::InvalidKeyLength;
            }
            alg.unwrap().into()
        });
        let ret = RcAeadCtx { ctx };
        this.write(ret);

        RcResult::Ok
    }

    pub unsafe extern "C" fn rc_aead_encrypt_in_place(
        &self,
        nonce: *const u8,
        nlen: usize,
        associated_data: *const u8,
        alen: usize,
        buf: *mut u8,
        blen: usize,
        tag: *mut u8,
        tlen: *mut usize,
    ) -> RcResult {
        let nonce = unsafe { slice::from_raw_parts(nonce, nlen) };
        let ad = unsafe { slice::from_raw_parts(associated_data, alen) };
        let buf = unsafe { slice::from_raw_parts_mut(buf, blen) };
        let tag_out = unsafe { slice::from_raw_parts_mut(tag, *tlen) };

        for_each_ctx! {&self.ctx, |cipher: &AlgTy| {
            let Ok(nonce) = nonce.try_into() else {
                return RcResult::InvalidNonceLength;
            };
            let Ok(tag) = cipher.encrypt_in_place_detached(nonce, ad, buf) else {
                return RcResult::CryptError;
            };

            if tag_out.len() < tag.len() {
                return RcResult::InvalidTagLength;
            }

            tag_out[..tag.len()].copy_from_slice(&tag);
            *tlen = tag.len();
            RcResult::Ok
        }, {
            RcResult::InvalidState
        }}
    }

    pub unsafe extern "C" fn rc_aead_decrypt_in_place(
        &self,
        nonce: *const u8,
        nlen: usize,
        associated_data: *const u8,
        alen: usize,
        buf: *mut u8,
        blen: usize,
        tag: *const u8,
        tlen: usize,
    ) -> RcResult {
        let nonce = unsafe { slice::from_raw_parts(nonce, nlen) };
        let ad = unsafe { slice::from_raw_parts(associated_data, alen) };
        let buf = unsafe { slice::from_raw_parts_mut(buf, blen) };
        let tag = unsafe { slice::from_raw_parts(tag, tlen) };

        for_each_ctx! {&self.ctx, |cipher: &AlgTy| {
            let Ok(nonce) = nonce.try_into() else {
                return RcResult::InvalidNonceLength;
            };
            let Ok(tag) = tag.try_into() else {
                return RcResult::InvalidTagLength;
            };
            let Ok(()) = cipher.decrypt_in_place_detached(nonce, ad, buf, tag) else {
                return RcResult::CryptError;
            };

            RcResult::Ok
        }, {
            RcResult::InvalidState
        }}
    }

    pub unsafe extern "C" fn rc_aead_deinit(this: *mut Self) {
        ptr::drop_in_place(this);
    }
}

impl From<Aes256Gcm> for AeadCtxInner {
    fn from(value: Aes256Gcm) -> Self {
        Self::Aes256Gcm(value)
    }
}

impl From<Aes128Gcm> for AeadCtxInner {
    fn from(value: Aes128Gcm) -> Self {
        Self::Aes128Gcm(value)
    }
}

impl From<ChaCha20Poly1305> for AeadCtxInner {
    fn from(value: ChaCha20Poly1305) -> Self {
        Self::ChaCha20Poly1305(value)
    }
}

/// Copy `src` to `dst` if it fits, otherwise set dlen to the needed length
unsafe fn copy_buf_result(src: &[u8], dst: *mut u8, dlen: &mut usize) -> RcResult {
    let dst = unsafe { slice::from_raw_parts_mut(dst, *dlen) };

    if src.len() > dst.len() {
        *dlen = src.len();
        RcResult::InvalidKeyLength
    } else {
        dst[..src.len()].copy_from_slice(src);
        *dlen = src.len();
        RcResult::Ok
    }
}
