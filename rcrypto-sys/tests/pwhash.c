#include "test_framework.h"

void test_argon2() {
    char *pw = "password";
    char *salt = "c2FsdHlzYWx0eXNhbHR5";
    char *expected = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHlzYWx0eXNhbHR5$LTCCralPbFpMyrU5fOFhSIR37CV6B19KICx1uph6jn0";
    int pwlen = strlen(pw);
    int saltlen = strlen(salt);
    size_t newout;

    uchar out[RC_PWHASH_STRBYTES+100];

    int cres = rc_pwhash_argon2((uchar*)pw, pwlen, (uchar*)salt, saltlen, out,
                                RC_PWHASH_STRBYTES, &newout);
    TEST_ASSERT_EQUAL(0, cres);
    // TEST_ASSERT_EQUAL(strlen(expected), newout); // FIXME
    TEST_ASSERT_EQUAL_STRING(expected, out);
    printf("pw: %s\n", out);

    int vres = rc_pwhash_argon2_verify((uchar*)pw, pwlen, (uchar*)salt, saltlen);
    TEST_ASSERT_EQUAL(0, vres);
}

int main() {
    UNITY_BEGIN();
    
    RUN_TEST(test_argon2);
    
    return UNITY_END();
}
