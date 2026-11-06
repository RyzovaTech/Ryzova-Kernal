/* SPDX-License-Identifier: AGPL-3.0-only */
#include <unistd.h>

int main(void)
{
    static const char message[] = "FLEX_MACOS_M1_REFERENCE\n";
    return write(STDOUT_FILENO, message, sizeof message - 1) ==
           (ssize_t)(sizeof message - 1) ? 37 : 1;
}
