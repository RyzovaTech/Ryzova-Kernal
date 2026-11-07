/* SPDX-License-Identifier: GPL-3.0-only */
static long syscall3(long number, long first, long second, long third)
{
    long result;
    __asm__ volatile("syscall" : "=a"(result)
                     : "a"(number), "D"(first), "S"(second), "d"(third)
                     : "rcx", "r11", "memory");
    return result;
}

long app_main(void)
{
    static const char input[] = "/home/share/input.json";
    static const char created[] = "/home/share/c2-created.json";
    long fd = syscall3(2, (long)input, 0, 0);
    if(fd < 0)
        return 11;
    if(syscall3(1, fd, (long)"X", 1) != -9)
        return 12;
    if(syscall3(3, fd, 0, 0) != 0)
        return 13;
    if(syscall3(2, (long)created, 0301, 0600) != -13)
        return 14;
    if(syscall3(76, (long)input, 0, 0) != -13)
        return 15;
    return 0;
}
