#ifndef AX201_SAE_TEST_SYS_SYSTM_H
#define AX201_SAE_TEST_SYS_SYSTM_H
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
static inline void
ax201_test_explicit_bzero(void *ptr, size_t length)
{
	volatile unsigned char *p = (volatile unsigned char *)ptr;
	while (length-- != 0)
		*p++ = 0;
}
#define explicit_bzero ax201_test_explicit_bzero
#endif
