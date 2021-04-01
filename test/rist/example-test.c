/* librist. Copyright © 2020 SipRadius LLC. All right reserved.
 * Author: Gijs Peskens <gijs@in2ip.nl>
 * Author: Sergio Ammirata, Ph.D. <sergio@ammirata.net>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <assert.h>
#include "librist.h"
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <cmocka.h>

static void basic_test(void** state) {
    (void)state;
    assert(1 == 1);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(basic_test)
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
