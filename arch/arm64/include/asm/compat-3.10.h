/*
 * Compatibility header for backporting 4.14 features to kernel 3.10
 * Copyright (C) 2025  
 */

#ifndef __ASM_COMPAT_3_10_H
#define __ASM_COMPAT_3_10_H

/* __pa_symbol - convert a symbol address to physical address */
#ifndef __pa_symbol
#define __pa_symbol(x)	__pa(RELOC_HIDE((unsigned long)(x), 0))
#endif

/* GENMASK - create a contiguous bitmask */
#ifndef GENMASK
#define GENMASK(h, l) \
	(((~0UL) << (l)) & (~0UL >> (BITS_PER_LONG - 1 - (h))))
#endif

/* FIX_TEXT_POKE0 - fixmap index for text patching */
#ifndef FIX_TEXT_POKE0
#define FIX_TEXT_POKE0 (FIX_EARLYCON_MEM_BASE + 1)
#endif

/* stop_machine_cpuslocked - wrapper for stop_machine */
#ifndef stop_machine_cpuslocked
#define stop_machine_cpuslocked(fn, data, cpus) stop_machine(fn, data, cpus)
#endif

#endif /* __ASM_COMPAT_3_10_H */
