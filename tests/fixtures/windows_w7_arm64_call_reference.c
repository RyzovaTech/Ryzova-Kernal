/* SPDX-License-Identifier: AGPL-3.0-only */
/* Windows ARM64 compiler-generated stack / LR / BL mini-program.
 * Volatile input keeps the call real at -O0 and meaningful at -O2. */
__declspec(noinline) int cw_w7_add_one(int value) {
    return value + 1;
}
int main(void) {
    volatile int operand = 36;
    return cw_w7_add_one(operand);
}
