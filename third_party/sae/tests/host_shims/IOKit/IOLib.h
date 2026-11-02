#ifndef AX201_SAE_TEST_IOKIT_IOLIB_H
#define AX201_SAE_TEST_IOKIT_IOLIB_H
#include <stdlib.h>
#include <string.h>
static inline void *
IOMallocZero(size_t length)
{
	return calloc(1, length);
}
static inline void
IOFree(void *ptr, size_t length)
{
	if (ptr != NULL) {
		memset(ptr, 0, length);
		free(ptr);
	}
}
#endif
