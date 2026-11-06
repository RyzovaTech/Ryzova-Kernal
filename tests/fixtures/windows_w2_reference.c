/* SPDX-License-Identifier: AGPL-3.0-only */
/* Leaf, import-free PE32+ reference: Windows and Flex must compute the same DWORD. */
#if !defined(_WIN64)
#error AMD64 Windows target required
#endif
typedef unsigned long DWORD;
typedef char dword_must_be_32[(sizeof(DWORD)==4)?1:-1];
volatile DWORD values[2] = {0x12345000UL, 0x678UL};
DWORD flex_entry(void)
{
    return values[0] + values[1];
}
