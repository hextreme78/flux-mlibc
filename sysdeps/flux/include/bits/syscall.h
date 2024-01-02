#ifndef MLIBC_SYSCALL_H
#define MLIBC_SYSCALL_H

#include <bits/syscall_defs.h>

#ifdef __cplusplus
extern "C" {
#endif

long syscall(long number, ...);

#ifdef __cplusplus
}
#endif

#endif

