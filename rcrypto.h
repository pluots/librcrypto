/*
* This file is automatically generated upon running
* `cargo +nightly build`. Do not modify by hand.
*/
#define RC_AEAD_AES128GCM_NONCEBYTES 12
#define RC_AEAD_AES128GCM_KEYBYTES 16
#define RC_AEAD_AES128GCM_MACBYTES 16
#define RC_AEAD_AES256GCM_NONCEBYTES 12
#define RC_AEAD_AES256GCM_KEYBYTES 32
#define RC_AEAD_AES256GCM_MACBYTES 16
#define RC_AEAD_CHACHA20POLY1305_NONCEBYTES 12
#define RC_AEAD_CHACHA20POLY1305_KEYBYTES 32
#define RC_AEAD_CHACHA20POLY1305_MACBYTES 16
#define RC_AEAD_XCHACHA20POLY1305_NONCEBYTES 24
#define RC_AEAD_XCHACHA20POLY1305_KEYBYTES 32
#define RC_AEAD_XCHACHA20POLY1305_MACBYTES 16
#define RC_SECRETBOX_KEYBYTES 24
#define RC_SECRETBOX_NONCEBYTES 32
#define RC_SECRETBOX_MACBYTES 16
#define RC_PWHASH_STRBYTES 128
#define RC_PWHASH_SALT_RECOMMENDED_BYTES 16
#define RC_PWHASH_SALT_MIN_BYTES 4
#define RC_PWHASH_SALT_MAX_BYTES 64


#include <stdint.h>

/**
 * Maximum length for a password output string. Actual value may be shorter
 */
#define RC_PWHASH_STRBYTES 128







typedef enum RcB64Variant {
  RcB64Original,
  RcB64OriginalUnpadded,
  RcB64Url,
  RcB64UrlUnpadded,
} RcB64Variant;

typedef enum RcBase64Result {
  RcB64Ok = 0,
  RcB64InvalidEncoding = -2,
  RcB64InvalidLength = -1,
} RcBase64Result;

typedef enum RcPwhashresult {
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
} RcPwhashresult;

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

extern const uint32_t RC_VERSION;

/**
 * Generate a nonce suitible for use with the
 *AES128-GCM
 * algorithm.
 *
 * # Safety
 *
 *`key` must be a valid buffer of length `RC_AEAD_AES128GCM_NONCEBYTES`
 */
void rc_aead_aes128gcm_noncegen(uint8_t nonce[RC_AEAD_AES128GCM_NONCEBYTES]);

/**
 * Generate a key suitible for use with the
 *AES128-GCM
 * algorithm.
 *
 * # Safety
 *
 *`key` must be a valid buffer of length `RC_AEAD_AES128GCM_KEYBYTES`
 */
void rc_aead_aes128gcm_keygen(uint8_t key[RC_AEAD_AES128GCM_KEYBYTES]);

/**
 * Encrypt a message using the AES128-GCM algorithm.
 *
 * Returns 0 if successful, -1 otherwise. Parameters:
 *
 * - `msg`: an input and output buffer that will be encrypted
 * - `mlen`: length of the message to be encrypted
 * - `mac`: an output buffer where the authentecation tag will be written. Must be
 *   `RC_AEAD_AES128GCM_MACBYTES` bytes in length.
 * - `nonce`: a number used once, AKA initialization vector. This does not have to be
 *   confidential and can be stored with the message; however, it may not be reused
 *   for further encryption. Must be
 *   `RC_AEAD_AES128GCM_NONCEBYTES` bytes in length.
 * - `key`: the key used to encrypt the message. Must be
 *   `RC_AEAD_AES128GCM_KEYBYTES` bytes in length.
 *
 * # Safety
 *
 * `msg` must point to a valid buffer that is at least `mlen` in length.
 */
int8_t rc_aead_aes128gcm_encrypt(uint8_t *msg,
                                 uintptr_t mlen,
                                 uint8_t mac[RC_AEAD_AES128GCM_MACBYTES],
                                 const uint8_t nonce[RC_AEAD_AES128GCM_NONCEBYTES],
                                 const uint8_t key[RC_AEAD_AES128GCM_KEYBYTES]);

/**
 * Encrypt a message using the AES128-GCM algorithm with additional data
 * (any data that gets added to the MAC input).
 *
 * # Safety
 *
 *Safety requirements are the same as [`rc_aead_aes128gcm_encrypt`],
 * with the additional requirement that `*ad` is valid for `adlen`.
 */
int8_t rc_aead_aes128gcm_encrypt_ad(uint8_t *msg,
                                    uintptr_t mlen,
                                    uint8_t mac[RC_AEAD_AES128GCM_MACBYTES],
                                    const uint8_t nonce[RC_AEAD_AES128GCM_NONCEBYTES],
                                    const uint8_t key[RC_AEAD_AES128GCM_KEYBYTES],
                                    const uint8_t *ad,
                                    uintptr_t adlen);

/**
 * Decrypt a message using the AES128-GCM algorithm.
 *
 * Returns 0 if successful, -1 otherwise. Parameters:
 *
 * - `msg`: an input and output buffer that will be decrypted
 * - `mlen`: length of the message to be decrypted
 * - `mac`: an output buffer where the authentecation tag will be written. Must be
 *   `RC_AEAD_AES128GCM_MACBYTES` bytes in length.
 * - `nonce`: a number used once, AKA initialization vector. This does not have to be
 *   confidential and can be stored with the message; however, it may not be reused
 *   for further encryption. Must be
 *   `RC_AEAD_AES128GCM_NONCEBYTES` bytes in length.
 * - `key`: the key used to encrypt the message. Must be
 *   `RC_AEAD_AES128GCM_KEYBYTES` bytes in length.
 *
 * # Safety
 *
 * `msg` must point to a valid buffer that is at least `mlen` in length.
 */
int8_t rc_aead_aes128gcm_decrypt(uint8_t *msg,
                                 uintptr_t mlen,
                                 const uint8_t mac[RC_AEAD_AES128GCM_MACBYTES],
                                 const uint8_t nonce[RC_AEAD_AES128GCM_NONCEBYTES],
                                 const uint8_t key[RC_AEAD_AES128GCM_KEYBYTES]);

/**
 * Decrypt a message using the AES128-GCM algorithm with additional data
 * (any data that gets added to the MAC input).
 *
 * # Safety
 *
 *Safety requirements are the same as [`rc_aead_aes128gcm_decrypt`],
 * with the additional requirement that `*ad` is valid for `adlen`.
 */
int8_t rc_aead_aes128gcm_decrypt_ad(uint8_t *msg,
                                    uintptr_t mlen,
                                    const uint8_t mac[RC_AEAD_AES128GCM_MACBYTES],
                                    const uint8_t nonce[RC_AEAD_AES128GCM_NONCEBYTES],
                                    const uint8_t key[RC_AEAD_AES128GCM_KEYBYTES],
                                    const uint8_t *ad,
                                    uintptr_t adlen);

/**
 * Generate a nonce suitible for use with the
 *AES256-GCM
 * algorithm.
 *
 * # Safety
 *
 *`key` must be a valid buffer of length `RC_AEAD_AES256GCM_NONCEBYTES`
 */
void rc_aead_aes256gcm_noncegen(uint8_t nonce[RC_AEAD_AES256GCM_NONCEBYTES]);

/**
 * Generate a key suitible for use with the
 *AES256-GCM
 * algorithm.
 *
 * # Safety
 *
 *`key` must be a valid buffer of length `RC_AEAD_AES256GCM_KEYBYTES`
 */
void rc_aead_aes256gcm_keygen(uint8_t key[RC_AEAD_AES256GCM_KEYBYTES]);

/**
 * Encrypt a message using the AES256-GCM algorithm.
 *
 * Returns 0 if successful, -1 otherwise. Parameters:
 *
 * - `msg`: an input and output buffer that will be encrypted
 * - `mlen`: length of the message to be encrypted
 * - `mac`: an output buffer where the authentecation tag will be written. Must be
 *   `RC_AEAD_AES256GCM_MACBYTES` bytes in length.
 * - `nonce`: a number used once, AKA initialization vector. This does not have to be
 *   confidential and can be stored with the message; however, it may not be reused
 *   for further encryption. Must be
 *   `RC_AEAD_AES256GCM_NONCEBYTES` bytes in length.
 * - `key`: the key used to encrypt the message. Must be
 *   `RC_AEAD_AES256GCM_KEYBYTES` bytes in length.
 *
 * # Safety
 *
 * `msg` must point to a valid buffer that is at least `mlen` in length.
 */
int8_t rc_aead_aes256gcm_encrypt(uint8_t *msg,
                                 uintptr_t mlen,
                                 uint8_t mac[RC_AEAD_AES256GCM_MACBYTES],
                                 const uint8_t nonce[RC_AEAD_AES256GCM_NONCEBYTES],
                                 const uint8_t key[RC_AEAD_AES256GCM_KEYBYTES]);

/**
 * Encrypt a message using the AES256-GCM algorithm with additional data
 * (any data that gets added to the MAC input).
 *
 * # Safety
 *
 *Safety requirements are the same as [`rc_aead_aes256gcm_encrypt`],
 * with the additional requirement that `*ad` is valid for `adlen`.
 */
int8_t rc_aead_aes256gcm_encrypt_ad(uint8_t *msg,
                                    uintptr_t mlen,
                                    uint8_t mac[RC_AEAD_AES256GCM_MACBYTES],
                                    const uint8_t nonce[RC_AEAD_AES256GCM_NONCEBYTES],
                                    const uint8_t key[RC_AEAD_AES256GCM_KEYBYTES],
                                    const uint8_t *ad,
                                    uintptr_t adlen);

/**
 * Decrypt a message using the AES256-GCM algorithm.
 *
 * Returns 0 if successful, -1 otherwise. Parameters:
 *
 * - `msg`: an input and output buffer that will be decrypted
 * - `mlen`: length of the message to be decrypted
 * - `mac`: an output buffer where the authentecation tag will be written. Must be
 *   `RC_AEAD_AES256GCM_MACBYTES` bytes in length.
 * - `nonce`: a number used once, AKA initialization vector. This does not have to be
 *   confidential and can be stored with the message; however, it may not be reused
 *   for further encryption. Must be
 *   `RC_AEAD_AES256GCM_NONCEBYTES` bytes in length.
 * - `key`: the key used to encrypt the message. Must be
 *   `RC_AEAD_AES256GCM_KEYBYTES` bytes in length.
 *
 * # Safety
 *
 * `msg` must point to a valid buffer that is at least `mlen` in length.
 */
int8_t rc_aead_aes256gcm_decrypt(uint8_t *msg,
                                 uintptr_t mlen,
                                 const uint8_t mac[RC_AEAD_AES256GCM_MACBYTES],
                                 const uint8_t nonce[RC_AEAD_AES256GCM_NONCEBYTES],
                                 const uint8_t key[RC_AEAD_AES256GCM_KEYBYTES]);

/**
 * Decrypt a message using the AES256-GCM algorithm with additional data
 * (any data that gets added to the MAC input).
 *
 * # Safety
 *
 *Safety requirements are the same as [`rc_aead_aes256gcm_decrypt`],
 * with the additional requirement that `*ad` is valid for `adlen`.
 */
int8_t rc_aead_aes256gcm_decrypt_ad(uint8_t *msg,
                                    uintptr_t mlen,
                                    const uint8_t mac[RC_AEAD_AES256GCM_MACBYTES],
                                    const uint8_t nonce[RC_AEAD_AES256GCM_NONCEBYTES],
                                    const uint8_t key[RC_AEAD_AES256GCM_KEYBYTES],
                                    const uint8_t *ad,
                                    uintptr_t adlen);

/**
 * Generate a nonce suitible for use with the
 *ChaCha20-Poly1305
 * algorithm.
 *
 * # Safety
 *
 *`key` must be a valid buffer of length `RC_AEAD_CHACHA20POLY1305_NONCEBYTES`
 */
void rc_aead_chacha20poly1305_noncegen(uint8_t nonce[RC_AEAD_CHACHA20POLY1305_NONCEBYTES]);

/**
 * Generate a key suitible for use with the
 *ChaCha20-Poly1305
 * algorithm.
 *
 * # Safety
 *
 *`key` must be a valid buffer of length `RC_AEAD_CHACHA20POLY1305_KEYBYTES`
 */
void rc_aead_chacha20poly1305_keygen(uint8_t key[RC_AEAD_CHACHA20POLY1305_KEYBYTES]);

/**
 * Encrypt a message using the ChaCha20-Poly1305 algorithm.
 *
 * Returns 0 if successful, -1 otherwise. Parameters:
 *
 * - `msg`: an input and output buffer that will be encrypted
 * - `mlen`: length of the message to be encrypted
 * - `mac`: an output buffer where the authentecation tag will be written. Must be
 *   `RC_AEAD_CHACHA20POLY1305_MACBYTES` bytes in length.
 * - `nonce`: a number used once, AKA initialization vector. This does not have to be
 *   confidential and can be stored with the message; however, it may not be reused
 *   for further encryption. Must be
 *   `RC_AEAD_CHACHA20POLY1305_NONCEBYTES` bytes in length.
 * - `key`: the key used to encrypt the message. Must be
 *   `RC_AEAD_CHACHA20POLY1305_KEYBYTES` bytes in length.
 *
 * # Safety
 *
 * `msg` must point to a valid buffer that is at least `mlen` in length.
 */
int8_t rc_aead_chacha20poly1305_encrypt(uint8_t *msg,
                                        uintptr_t mlen,
                                        uint8_t mac[RC_AEAD_CHACHA20POLY1305_MACBYTES],
                                        const uint8_t nonce[RC_AEAD_CHACHA20POLY1305_NONCEBYTES],
                                        const uint8_t key[RC_AEAD_CHACHA20POLY1305_KEYBYTES]);

/**
 * Encrypt a message using the ChaCha20-Poly1305 algorithm with additional data
 * (any data that gets added to the MAC input).
 *
 * # Safety
 *
 *Safety requirements are the same as [`rc_aead_chacha20poly1305_encrypt`],
 * with the additional requirement that `*ad` is valid for `adlen`.
 */
int8_t rc_aead_chacha20poly1305_encrypt_ad(uint8_t *msg,
                                           uintptr_t mlen,
                                           uint8_t mac[RC_AEAD_CHACHA20POLY1305_MACBYTES],
                                           const uint8_t nonce[RC_AEAD_CHACHA20POLY1305_NONCEBYTES],
                                           const uint8_t key[RC_AEAD_CHACHA20POLY1305_KEYBYTES],
                                           const uint8_t *ad,
                                           uintptr_t adlen);

/**
 * Decrypt a message using the ChaCha20-Poly1305 algorithm.
 *
 * Returns 0 if successful, -1 otherwise. Parameters:
 *
 * - `msg`: an input and output buffer that will be decrypted
 * - `mlen`: length of the message to be decrypted
 * - `mac`: an output buffer where the authentecation tag will be written. Must be
 *   `RC_AEAD_CHACHA20POLY1305_MACBYTES` bytes in length.
 * - `nonce`: a number used once, AKA initialization vector. This does not have to be
 *   confidential and can be stored with the message; however, it may not be reused
 *   for further encryption. Must be
 *   `RC_AEAD_CHACHA20POLY1305_NONCEBYTES` bytes in length.
 * - `key`: the key used to encrypt the message. Must be
 *   `RC_AEAD_CHACHA20POLY1305_KEYBYTES` bytes in length.
 *
 * # Safety
 *
 * `msg` must point to a valid buffer that is at least `mlen` in length.
 */
int8_t rc_aead_chacha20poly1305_decrypt(uint8_t *msg,
                                        uintptr_t mlen,
                                        const uint8_t mac[RC_AEAD_CHACHA20POLY1305_MACBYTES],
                                        const uint8_t nonce[RC_AEAD_CHACHA20POLY1305_NONCEBYTES],
                                        const uint8_t key[RC_AEAD_CHACHA20POLY1305_KEYBYTES]);

/**
 * Decrypt a message using the ChaCha20-Poly1305 algorithm with additional data
 * (any data that gets added to the MAC input).
 *
 * # Safety
 *
 *Safety requirements are the same as [`rc_aead_chacha20poly1305_decrypt`],
 * with the additional requirement that `*ad` is valid for `adlen`.
 */
int8_t rc_aead_chacha20poly1305_decrypt_ad(uint8_t *msg,
                                           uintptr_t mlen,
                                           const uint8_t mac[RC_AEAD_CHACHA20POLY1305_MACBYTES],
                                           const uint8_t nonce[RC_AEAD_CHACHA20POLY1305_NONCEBYTES],
                                           const uint8_t key[RC_AEAD_CHACHA20POLY1305_KEYBYTES],
                                           const uint8_t *ad,
                                           uintptr_t adlen);

/**
 * Generate a nonce suitible for use with the
 *XChaCha20-Poly1305
 * algorithm.
 *
 * # Safety
 *
 *`key` must be a valid buffer of length `RC_AEAD_XCHACHA20POLY1305_NONCEBYTES`
 */
void rc_aead_xchacha20poly1305_noncegen(uint8_t nonce[RC_AEAD_XCHACHA20POLY1305_NONCEBYTES]);

/**
 * Generate a key suitible for use with the
 *XChaCha20-Poly1305
 * algorithm.
 *
 * # Safety
 *
 *`key` must be a valid buffer of length `RC_AEAD_XCHACHA20POLY1305_KEYBYTES`
 */
void rc_aead_xchacha20poly1305_keygen(uint8_t key[RC_AEAD_XCHACHA20POLY1305_KEYBYTES]);

/**
 * Encrypt a message using the XChaCha20-Poly1305 algorithm.
 *
 * Returns 0 if successful, -1 otherwise. Parameters:
 *
 * - `msg`: an input and output buffer that will be encrypted
 * - `mlen`: length of the message to be encrypted
 * - `mac`: an output buffer where the authentecation tag will be written. Must be
 *   `RC_AEAD_XCHACHA20POLY1305_MACBYTES` bytes in length.
 * - `nonce`: a number used once, AKA initialization vector. This does not have to be
 *   confidential and can be stored with the message; however, it may not be reused
 *   for further encryption. Must be
 *   `RC_AEAD_XCHACHA20POLY1305_NONCEBYTES` bytes in length.
 * - `key`: the key used to encrypt the message. Must be
 *   `RC_AEAD_XCHACHA20POLY1305_KEYBYTES` bytes in length.
 *
 * # Safety
 *
 * `msg` must point to a valid buffer that is at least `mlen` in length.
 */
int8_t rc_aead_xchacha20poly1305_encrypt(uint8_t *msg,
                                         uintptr_t mlen,
                                         uint8_t mac[RC_AEAD_XCHACHA20POLY1305_MACBYTES],
                                         const uint8_t nonce[RC_AEAD_XCHACHA20POLY1305_NONCEBYTES],
                                         const uint8_t key[RC_AEAD_XCHACHA20POLY1305_KEYBYTES]);

/**
 * Encrypt a message using the XChaCha20-Poly1305 algorithm with additional data
 * (any data that gets added to the MAC input).
 *
 * # Safety
 *
 *Safety requirements are the same as [`rc_aead_xchacha20poly1305_encrypt`],
 * with the additional requirement that `*ad` is valid for `adlen`.
 */
int8_t rc_aead_xchacha20poly1305_encrypt_ad(uint8_t *msg,
                                            uintptr_t mlen,
                                            uint8_t mac[RC_AEAD_XCHACHA20POLY1305_MACBYTES],
                                            const uint8_t nonce[RC_AEAD_XCHACHA20POLY1305_NONCEBYTES],
                                            const uint8_t key[RC_AEAD_XCHACHA20POLY1305_KEYBYTES],
                                            const uint8_t *ad,
                                            uintptr_t adlen);

/**
 * Decrypt a message using the XChaCha20-Poly1305 algorithm.
 *
 * Returns 0 if successful, -1 otherwise. Parameters:
 *
 * - `msg`: an input and output buffer that will be decrypted
 * - `mlen`: length of the message to be decrypted
 * - `mac`: an output buffer where the authentecation tag will be written. Must be
 *   `RC_AEAD_XCHACHA20POLY1305_MACBYTES` bytes in length.
 * - `nonce`: a number used once, AKA initialization vector. This does not have to be
 *   confidential and can be stored with the message; however, it may not be reused
 *   for further encryption. Must be
 *   `RC_AEAD_XCHACHA20POLY1305_NONCEBYTES` bytes in length.
 * - `key`: the key used to encrypt the message. Must be
 *   `RC_AEAD_XCHACHA20POLY1305_KEYBYTES` bytes in length.
 *
 * # Safety
 *
 * `msg` must point to a valid buffer that is at least `mlen` in length.
 */
int8_t rc_aead_xchacha20poly1305_decrypt(uint8_t *msg,
                                         uintptr_t mlen,
                                         const uint8_t mac[RC_AEAD_XCHACHA20POLY1305_MACBYTES],
                                         const uint8_t nonce[RC_AEAD_XCHACHA20POLY1305_NONCEBYTES],
                                         const uint8_t key[RC_AEAD_XCHACHA20POLY1305_KEYBYTES]);

/**
 * Decrypt a message using the XChaCha20-Poly1305 algorithm with additional data
 * (any data that gets added to the MAC input).
 *
 * # Safety
 *
 *Safety requirements are the same as [`rc_aead_xchacha20poly1305_decrypt`],
 * with the additional requirement that `*ad` is valid for `adlen`.
 */
int8_t rc_aead_xchacha20poly1305_decrypt_ad(uint8_t *msg,
                                            uintptr_t mlen,
                                            const uint8_t mac[RC_AEAD_XCHACHA20POLY1305_MACBYTES],
                                            const uint8_t nonce[RC_AEAD_XCHACHA20POLY1305_NONCEBYTES],
                                            const uint8_t key[RC_AEAD_XCHACHA20POLY1305_KEYBYTES],
                                            const uint8_t *ad,
                                            uintptr_t adlen);

/**
 * Generate a nonce suitible for use with the
 *XSalsa20-Poly1305
 * algorithm.
 *
 * # Safety
 *
 *`key` must be a valid buffer of length `RC_SECRETBOX_KEYBYTES`
 */
void rc_secretbox_keygen(uint8_t nonce[RC_SECRETBOX_KEYBYTES]);

/**
 * Generate a key suitible for use with the
 *XSalsa20-Poly1305
 * algorithm.
 *
 * # Safety
 *
 *`key` must be a valid buffer of length `RC_SECRETBOX_NONCEBYTES`
 */
void rc_secretbox_noncegen(uint8_t key[RC_SECRETBOX_NONCEBYTES]);

/**
 * Encrypt a message using the XSalsa20-Poly1305 algorithm.
 *
 * Returns 0 if successful, -1 otherwise. Parameters:
 *
 * - `msg`: an input and output buffer that will be encrypted
 * - `mlen`: length of the message to be encrypted
 * - `mac`: an output buffer where the authentecation tag will be written. Must be
 *   `RC_SECRETBOX_MACBYTES` bytes in length.
 * - `nonce`: a number used once, AKA initialization vector. This does not have to be
 *   confidential and can be stored with the message; however, it may not be reused
 *   for further encryption. Must be
 *   `RC_SECRETBOX_KEYBYTES` bytes in length.
 * - `key`: the key used to encrypt the message. Must be
 *   `RC_SECRETBOX_NONCEBYTES` bytes in length.
 *
 * # Safety
 *
 * `msg` must point to a valid buffer that is at least `mlen` in length.
 */
int8_t rc_secretbox_detached(uint8_t *msg,
                             uintptr_t mlen,
                             uint8_t mac[RC_SECRETBOX_MACBYTES],
                             const uint8_t nonce[RC_SECRETBOX_KEYBYTES],
                             const uint8_t key[RC_SECRETBOX_NONCEBYTES]);

/**
 * Encrypt a message using the XSalsa20-Poly1305 algorithm with additional data
 * (any data that gets added to the MAC input).
 *
 * # Safety
 *
 *Safety requirements are the same as [`rc_secretbox_detached`],
 * with the additional requirement that `*ad` is valid for `adlen`.
 */
int8_t rc_secretbox_detached_ad(uint8_t *msg,
                                uintptr_t mlen,
                                uint8_t mac[RC_SECRETBOX_MACBYTES],
                                const uint8_t nonce[RC_SECRETBOX_KEYBYTES],
                                const uint8_t key[RC_SECRETBOX_NONCEBYTES],
                                const uint8_t *ad,
                                uintptr_t adlen);

/**
 * Decrypt a message using the XSalsa20-Poly1305 algorithm.
 *
 * Returns 0 if successful, -1 otherwise. Parameters:
 *
 * - `msg`: an input and output buffer that will be decrypted
 * - `mlen`: length of the message to be decrypted
 * - `mac`: an output buffer where the authentecation tag will be written. Must be
 *   `RC_SECRETBOX_MACBYTES` bytes in length.
 * - `nonce`: a number used once, AKA initialization vector. This does not have to be
 *   confidential and can be stored with the message; however, it may not be reused
 *   for further encryption. Must be
 *   `RC_SECRETBOX_KEYBYTES` bytes in length.
 * - `key`: the key used to encrypt the message. Must be
 *   `RC_SECRETBOX_NONCEBYTES` bytes in length.
 *
 * # Safety
 *
 * `msg` must point to a valid buffer that is at least `mlen` in length.
 */
int8_t rc_secretbox_open_detached(uint8_t *msg,
                                  uintptr_t mlen,
                                  const uint8_t mac[RC_SECRETBOX_MACBYTES],
                                  const uint8_t nonce[RC_SECRETBOX_KEYBYTES],
                                  const uint8_t key[RC_SECRETBOX_NONCEBYTES]);

/**
 * Decrypt a message using the XSalsa20-Poly1305 algorithm with additional data
 * (any data that gets added to the MAC input).
 *
 * # Safety
 *
 *Safety requirements are the same as [`rc_secretbox_open_detached`],
 * with the additional requirement that `*ad` is valid for `adlen`.
 */
int8_t rc_secretbox_open_detached_ad(uint8_t *msg,
                                     uintptr_t mlen,
                                     const uint8_t mac[RC_SECRETBOX_MACBYTES],
                                     const uint8_t nonce[RC_SECRETBOX_KEYBYTES],
                                     const uint8_t key[RC_SECRETBOX_NONCEBYTES],
                                     const uint8_t *ad,
                                     uintptr_t adlen);

/**
 * Constant-time base64 encoding (bin -> b64)
 *
 * - `variant`: the encoding scheme to use
 * - `bin`: pointer to date to be encoded
 * - `bin_len`: length of data to be encoded, in bytes
 * - `b64`: destination of base64-encoded data
 * - `b64_maxlen`: the length of buffer `b64`. If this is not long enough for the encoded
 *   data, the output will be truncated.
 * - `b64_len`: length of the encoded data after being written
 *
 * # Safety
 *
 * All buffers must be valid for their associated lengths (`bin` -> `bin_len`,
 * `b64` -> `b64_maxlen`).
 */
enum RcBase64Result rc_base64_encode_ct(enum RcB64Variant variant,
                                        const uint8_t *bin,
                                        uintptr_t bin_len,
                                        uint8_t *b64,
                                        uintptr_t b64_maxlen,
                                        uintptr_t *b64_len);

/**
 * Constant-time base64 decoding (b64 -> bin)
 *
 * - `variant`: the encoding scheme to use
 * - `b64`: pointer to date to be decoded
 * - `b64_len`: length of data to be decoded, in bytes
 * - `bin`: destination of binary data
 * - `bin_maxlen`: the length of buffer `bin`. If this is not long enough for the encoded
 *   data, the output will be truncated.
 * - `b64_len`: length of the encoded data after being written
 *
 * # Safety
 *
 * All buffers must be valid for their associated lengths (`bin` -> `bin_len`,
 * `b64` -> `b64_maxlen`).
 */
enum RcBase64Result rc_base64_decode_ct(enum RcB64Variant variant,
                                        const uint8_t *b64,
                                        uintptr_t b64len,
                                        uint8_t *bin,
                                        uintptr_t bin_maxlen,
                                        uintptr_t *bin_len);

/**
 * Determine the length required to encode data with a specific base64 variant.
 */
uintptr_t rc_base64_encoded_len(enum RcB64Variant variant, uintptr_t len);

/**
 * Hash a password with argon2id v19
 *
 * # Safety
 *
 * - `pw` is `pwlen` in length
 * - `salt` is `saltlen` in length
 * - `out` is `out_maxlen` in length
 */
enum RcPwhashresult rc_pwhash_argon2(const uint8_t *pw,
                                     uintptr_t pwlen,
                                     const uint8_t *salt,
                                     uintptr_t saltlen,
                                     uint8_t *out,
                                     uintptr_t out_maxlen,
                                     uintptr_t *outlen);

/**
 * Returns negative if error, +1 if incorrect but everything working, 0 if
 * correct.
 *
 * # Safety
 *
 * - `pw` is `pwlen`
 * - `hash` is `hlen`
 */
enum RcPwhashresult rc_pwhash_argon2_verify(const uint8_t *pw,
                                            uintptr_t pwlen,
                                            const uint8_t *hash,
                                            uintptr_t hlen);

/**
 * Zero a buffer
 *
 * # Safety
 *
 * `*ptr` must be valid for `len`
 */
void rc_zeroize(uint8_t *ptr, uintptr_t len);

#ifdef __cplusplus
} // extern "C"
#endif // __cplusplus
