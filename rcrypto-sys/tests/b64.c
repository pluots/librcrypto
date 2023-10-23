#include "test_framework.h"

void b64_runner(RcB64Variant var, char *expected, char *name) {
    const uchar msg[] = "Hello, world! <<?_?>> x";
    const int msglen = strlen((char*)msg);
    const int explen = strlen(expected);
    
    uchar out_enc[explen];
    uchar out_dec[msglen];
    size_t newlen = 0;
   
    const int outlen = rc_base64_encoded_len(var, strlen((char*)msg));
    TEST_ASSERT_EQUAL_INT_MESSAGE(explen, outlen, name);

    rc_base64_encode_ct(var, msg, msglen, out_enc, explen, &newlen);
    TEST_ASSERT_EQUAL_INT_MESSAGE(explen, newlen, name);
    TEST_ASSERT_EQUAL_MEMORY_MESSAGE(expected, out_enc, newlen, name);

    newlen = 0;
    rc_base64_decode_ct(var, out_enc, outlen, out_dec, msglen, &newlen);
    TEST_ASSERT_EQUAL_INT_MESSAGE(msglen, newlen, name);
    TEST_ASSERT_EQUAL_MEMORY_MESSAGE(msg, out_dec, newlen, name);
}

void test_b64_original() {
    b64_runner(RcB64Original, "SGVsbG8sIHdvcmxkISA8PD9fPz4+IHg=", "b64 original");
}

void test_b64_original_nopad() {
    b64_runner(RcB64OriginalUnpadded, "SGVsbG8sIHdvcmxkISA8PD9fPz4+IHg", "b64 original nopad");
}

void test_b64_url() {
    b64_runner(RcB64Url, "SGVsbG8sIHdvcmxkISA8PD9fPz4-IHg=", "b64 url");
}

void test_b64_url_nopad() {
    b64_runner(RcB64UrlUnpadded, "SGVsbG8sIHdvcmxkISA8PD9fPz4-IHg", "b64 url nopad");
}

int main() {
    UNITY_BEGIN();
    
    RUN_TEST(test_b64_original);
    RUN_TEST(test_b64_original_nopad);
    RUN_TEST(test_b64_url);
    RUN_TEST(test_b64_url_nopad);
    
    return UNITY_END();
}
