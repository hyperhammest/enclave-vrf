#include <stdint.h>

#define RETRY_LIMIT 10

#define DRNG_SUCCESS 1
#define DRNG_NOT_READY -1

#define _rdrand_step(x) ({ unsigned char err; asm volatile("rdrand %0; setc %1":"=r"(*x), "=qm"(err)); err; })

#define _rdrand16_step(x) _rdrand_step(x)

int rdrand_16(uint16_t* x, int retry)
{
	unsigned int i;
		if (retry)
		{
			for (i = 0; i < RETRY_LIMIT; i++)
			{
				if (_rdrand16_step(x))
					return DRNG_SUCCESS;
			}

			return DRNG_NOT_READY;
		}
		else
		{
				if (_rdrand16_step(x))
					return DRNG_SUCCESS;
				else
					return DRNG_NOT_READY;
		}
}

// only SGX2 support
uint64_t get_tsc()
{
    uint64_t a, d;
    asm volatile("rdtsc" : "=a"(a), "=d"(d));
    return (d << 32) | a;
}