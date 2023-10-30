#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 2, 0)
/* commit e9a688bcb19348862afe30d7c85bc37c4c293471 */
/* + changed get_random_u{8,16} */
/* + forced inlining */

/* © 2022 Jason A. Donenfeld <Jason@zx2c4.com> */
/* SPDX-License-Identifier: GPL-2.0 */

static inline __attribute__((__always_inline__)) u32
__get_random_u32_below(u32 ceil)
{
	/*
	 * This is the slow path for variable ceil. It is still fast, most of
	 * the time, by doing traditional reciprocal multiplication and
	 * opportunistically comparing the lower half to ceil itself, before
	 * falling back to computing a larger bound, and then rejecting samples
	 * whose lower half would indicate a range indivisible by ceil. The use
	 * of `-ceil % ceil` is analogous to `2^32 % ceil`, but is computable
	 * in 32-bits.
	 */
	u64 mult = (u64)ceil * get_random_u32();
	if (unlikely((u32)mult < ceil)) {
		u32 bound = -ceil % ceil;
		while (unlikely((u32)mult < bound))
			mult = (u64)ceil * get_random_u32();
	}
	return mult >> 32;
}

/*
 * Returns a random integer in the interval [0, ceil), with uniform
 * distribution, suitable for all uses. Fastest when ceil is a constant, but
 * still fast for variable ceil as well.
 */
static inline __attribute__((__always_inline__)) u32
get_random_u32_below(u32 ceil)
{
	if (!__builtin_constant_p(ceil))
		return __get_random_u32_below(ceil);

	/*
	 * For the fast path, below, all operations on ceil are precomputed by
	 * the compiler, so this incurs no overhead for checking pow2, doing
	 * divisions, or branching based on integer size. The resultant
	 * algorithm does traditional reciprocal multiplication (typically
	 * optimized by the compiler into shifts and adds), rejecting samples
	 * whose lower half would indicate a range indivisible by ceil.
	 */
	BUILD_BUG_ON_MSG(!ceil, "get_random_u32_below() must take ceil > 0");
	if (ceil <= 1)
		return 0;
	for (;;) {
		if (ceil <= 1U << 8) {
			u32 mult = ceil * (u32)(u8)get_random_u32();
			if (likely(is_power_of_2(ceil) || (u8)mult >= (1U << 8) % ceil))
				return mult >> 8;
		} else if (ceil <= 1U << 16) {
			u32 mult = ceil * (u32)(u16)get_random_u32();
			if (likely(is_power_of_2(ceil) || (u16)mult >= (1U << 16) % ceil))
				return mult >> 16;
		} else {
			u64 mult = (u64)ceil * get_random_u32();
			if (likely(is_power_of_2(ceil) || (u32)mult >= -ceil % ceil))
				return mult >> 32;
		}
	}
}

#endif /* Linux < 6.2 */
