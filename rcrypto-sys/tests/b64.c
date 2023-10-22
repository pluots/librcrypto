#include "test_framework.h"

#define OUTLEN 100

void b64_runner(RcB64Variant var, char *expected, char *name) {
    uchar msg[] = "Hello, world!";
    uchar out1[OUTLEN];
    uchar out2[OUTLEN];
    size_t newlen;

    int msglen = strlen((char*)msg);
    int explen = strlen(expected);

    memset(out1, 0, OUTLEN);
    memset(out2, 0, OUTLEN);
    
    int outlen = rc_base64_encoded_len(RcB64Original, strlen((char*)msg));
    TEST_ASSERT_EQUAL_INT_MESSAGE(explen, outlen, name);
    
    rc_base64_encode_ct(var, msg, msglen, out1, OUTLEN, &newlen);
    TEST_ASSERT_EQUAL_INT_MESSAGE(explen, newlen, name);
    TEST_ASSERT_EQUAL_STRING_MESSAGE(expected, out1, name);
    printf("m %s\n", out1);

    rc_base64_decode_ct(var, out1, outlen, out2, OUTLEN, &newlen);
    TEST_ASSERT_EQUAL_INT_MESSAGE(msglen, newlen, name);
    TEST_ASSERT_EQUAL_STRING_MESSAGE(msg, out2, name);

    memset(out2 + newlen, 0, 20);
    printf("m %s\n", out2);
}

void test_b64_original() {
    b64_runner(RcB64Original, "SGVsbG8sIHdvcmxkIQ==", "b64 original");
}

void test_b64_original_nopad() {
    b64_runner(RcB64OriginalUnpadded, "SGVsbG8sIHdvcmxkIQ", "b64 original nopad");
}

void test_b64_url() {
    b64_runner(RcB64Url, "SGVsbG8sIHdvcmxkIQ==", "b64 url");
}

void test_b64_url_nopad() {
    b64_runner(RcB64UrlUnpadded, "SGVsbG8sIHdvcmxkIQ", "b64 url nopad");
}

int main() {
    UNITY_BEGIN();
    
    RUN_TEST(test_b64_original);
    RUN_TEST(test_b64_original_nopad);
    RUN_TEST(test_b64_url);
    RUN_TEST(test_b64_url_nopad);
    
    return UNITY_END();
}
