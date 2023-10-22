pub mod aeads {
    use aead::generic_array::GenericArray;
    use aead::AeadCore;
    use aead::{
        generic_array::typenum::{
            consts::{U12, U16},
            uint::UTerm,
        },
        AeadInPlace, KeyInit, KeySizeUser,
    };

    pub struct Aes128Gcm {
        // FIXME: zeroize
        key: GenericArray<u8, U16>,
    }

    impl KeySizeUser for Aes128Gcm {
        type KeySize = U16;
    }

    impl KeyInit for Aes128Gcm {
        fn new(key: &aead::Key<Self>) -> Self {
            Self { key: *key }
        }
    }

    impl AeadCore for Aes128Gcm {
        type NonceSize = U12;

        type TagSize = U16;

        type CiphertextOverhead = UTerm;
    }

    impl AeadInPlace for Aes128Gcm {
        fn encrypt_in_place_detached(
            &self,
            nonce: &aead::Nonce<Self>,
            associated_data: &[u8],
            buffer: &mut [u8],
        ) -> aead::Result<aead::Tag<Self>> {
            let mut tag: aead::Key<Self> = Default::default();
            let res = unsafe {
                rcrypto_sys::aeads::rc_aead_aes128gcm_encrypt_ad(
                    buffer.as_mut_ptr(),
                    buffer.len(),
                    tag.as_mut_ptr(),
                    nonce.as_ptr(),
                    self.key.as_ptr(),
                    associated_data.as_ptr(),
                    associated_data.len(),
                )
            };
            if res == 0 {
                Ok(tag)
            } else {
                Err(aead::Error)
            }
        }

        fn decrypt_in_place_detached(
            &self,
            nonce: &aead::Nonce<Self>,
            associated_data: &[u8],
            buffer: &mut [u8],
            tag: &aead::Tag<Self>,
        ) -> aead::Result<()> {
            let res = unsafe {
                rcrypto_sys::aeads::rc_aead_aes128gcm_decrypt_ad(
                    buffer.as_mut_ptr(),
                    buffer.len(),
                    tag.as_ptr(),
                    nonce.as_ptr(),
                    self.key.as_ptr(),
                    associated_data.as_ptr(),
                    associated_data.len(),
                )
            };
            if res == 0 {
                Ok(())
            } else {
                Err(aead::Error)
            }
        }
    }
}
