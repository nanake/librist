#include <assert.h>
#include "librist.h"

void basic_test() {
    assert(1 == 0);
}

int main(int argc, char* argv[]) {
    (void)argc;
    (void)argv;

    basic_test();

    return 0;
}
