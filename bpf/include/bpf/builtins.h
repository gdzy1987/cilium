/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2016-2020 Authors of Cilium */

#ifndef __BPF_BUILTINS__
#define __BPF_BUILTINS__

#include "compiler.h"

#ifndef lock_xadd
# define lock_xadd(P, V)	((void) __sync_fetch_and_add((P), (V)))
#endif

#define __it(x, op) (x -= sizeof(__u##op))

static __always_inline void __bpf_ua_memset(void *d, const __u8 c,
					    const __u64 len)
{
	switch (len) {
#define __it_set(a, b, op) (*(__u##op *)__it(a, op)) = b
	case 64: __it_set(d, c, 64);
	case 56: __it_set(d, c, 64);
	case 48: __it_set(d, c, 64);
	case 40: __it_set(d, c, 64);
	case 32: __it_set(d, c, 64);
	case 24: __it_set(d, c, 64);
	case 16: __it_set(d, c, 64);
	case  8: __it_set(d, c, 64);
		break;
	case 60: __it_set(d, c, 64);
	case 52: __it_set(d, c, 64);
	case 44: __it_set(d, c, 64);
	case 36: __it_set(d, c, 64);
	case 28: __it_set(d, c, 64);
	case 20: __it_set(d, c, 64);
	case 12: __it_set(d, c, 64);
	case  4: __it_set(d, c, 32);
		break;
	default:
		 /* Crappy slow since it cannot make any assumptions
		  * about alignment & underlying efficient unaligned
		  * access on the target we're running.
		  */
		__builtin_memset(d, c, len);
		break;
	}
}

static __always_inline void __bpf_ua_memcpy(void *d, void *s,
					    const __u64 len)
{
	switch (len) {
#define __it_mov(a, b, op) (*(__u##op *)__it(a, op)) = (*(__u##op *)__it(b, op))
	case 64: __it_mov(d, s, 64);
	case 56: __it_mov(d, s, 64);
	case 48: __it_mov(d, s, 64);
	case 40: __it_mov(d, s, 64);
	case 32: __it_mov(d, s, 64);
	case 24: __it_mov(d, s, 64);
	case 16: __it_mov(d, s, 64);
	case  8: __it_mov(d, s, 64);
		break;
	case 60: __it_mov(d, s, 64);
	case 52: __it_mov(d, s, 64);
	case 44: __it_mov(d, s, 64);
	case 36: __it_mov(d, s, 64);
	case 28: __it_mov(d, s, 64);
	case 20: __it_mov(d, s, 64);
	case 12: __it_mov(d, s, 64);
	case  4: __it_mov(d, s, 32);
		break;
	default:
		 /* Crappy slow since it cannot make any assumptions
		  * about alignment & underlying efficient unaligned
		  * access on the target we're running.
		  */
		__builtin_memcpy(d, s, len);
		break;
	}
}

#ifndef memset
# define memset(S, C, N)	__bpf_ua_memset((S), (C), (N))
#endif

#ifndef memcpy
# define memcpy(D, S, N)	__bpf_ua_memcpy((D), (S), (N))
#endif

#ifndef memmove
# define memmove(D, S, N)	__builtin_memmove((D), (S), (N))
#endif

/* NOTE: https://llvm.org/bugs/show_bug.cgi?id=26218 */
#ifndef memcmp
# define memcmp(A, B, N)	__builtin_memcmp((A), (B), (N))
#endif

#endif /* __BPF_BUILTINS__ */
