#ifndef _LINUX_NOSPEC_H
#define _LINUX_NOSPEC_H

static inline unsigned long array_index_nospec(unsigned long index, unsigned long size)
{
	if (index >= size)
		return size;
	return index;
}

#endif /* _LINUX_NOSPEC_H */
