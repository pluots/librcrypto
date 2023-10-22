#include "test_framework.h"

void test_zeroize() {
    uchar buf[] = "Hello, world!";
    char msg[100];
    int len = strlen((char*)buf);

    rc_zeroize(buf, len);

    for (int i=0; i<len; ++i) {
        sprintf(msg, "at character %d", i);
        TEST_ASSERT_EQUAL_MESSAGE(0, buf[i], msg);
    }
}

int main() {
    UNITY_BEGIN();
    
    RUN_TEST(test_zeroize);
    
    return UNITY_END();
}
