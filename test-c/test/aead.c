#include <string.h>
#include <stdint.h>
#include "rcrypto.h"
#include "unity.h"

typedef unsigned char uchar;

#define MAKE_AEAD_TEST(name, upper) \
    void test_ ## name () { \
        aead_test_runner( \
            "Testing algorithm '" #name "'", \
            RC_AEAD_ ## upper ## _KEYBYTES, \
            RC_AEAD_ ## upper ## _NONCEBYTES, \
            RC_AEAD_ ## upper ## _MACBYTES, \
            rc_aead_ ## name ## _noncegen, \
            rc_aead_ ## name ## _keygen, \
            rc_aead_ ## name ## _encrypt, \
            rc_aead_ ## name ## _decrypt \
        ); \
    }

void aead_test_runner(
    char *name,
    int klen,
    int nlen,
    int tlen,
    void (*gen_nonce)(uchar*),
    void (*gen_key)(uchar*),
    int8_t (*encrypt)(uchar*, size_t, uchar*, const uchar*, const uchar*),    
    int8_t (*decrypt)(uchar*, size_t, const uchar*, const uchar*, const uchar*)   
) {
    unsigned char msg[] = "Test encryption";
    int mlen = strlen((char*)msg);
    unsigned char orig[mlen];
    memcpy(orig, msg, mlen);
    unsigned char key[klen];
    unsigned char nonce[nlen];
    unsigned char mac[tlen];

    gen_nonce(nonce);
    gen_key(key);

    int eres = encrypt(msg, mlen, mac, nonce, key);
    
    TEST_ASSERT_EQUAL_INT_MESSAGE(eres, 0, name);
    TEST_ASSERT_NOT_EQUAL_UINT64_MESSAGE(*(uint64_t*)msg, *(uint64_t*)orig, name);
    
    int dres = decrypt(msg, mlen, mac, nonce, key);

    TEST_ASSERT_EQUAL_INT_MESSAGE(dres, 0, name);
    TEST_ASSERT_EQUAL_MEMORY_MESSAGE(orig, msg, mlen, name);
}

MAKE_AEAD_TEST(aes128gcm, AES128GCM)
MAKE_AEAD_TEST(aes256gcm, AES256GCM)
MAKE_AEAD_TEST(chacha20poly1305, CHACHA20POLY1305)
MAKE_AEAD_TEST(xchacha20poly1305, XCHACHA20POLY1305)

int main() {
    UNITY_BEGIN();
    
    RUN_TEST(test_aes128gcm);
    RUN_TEST(test_aes256gcm);
    RUN_TEST(test_chacha20poly1305);
    RUN_TEST(test_xchacha20poly1305);
    
    return UNITY_END();
}
