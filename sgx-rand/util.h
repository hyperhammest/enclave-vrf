#include <stdint.h>

#define RETRY_LIMIT 10

#define DRNG_SUCCESS 1
#define DRNG_NOT_READY -1

#define _rdrand_step(x) ({ unsigned char err; asm volatile("rdrand %0; setc %1":"=r"(*x), "=qm"(err)); err; })

#define _rdrand16_step(x) _rdrand_step(x)

#include <cpuid.h>
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
    return 0;
}

// only SGX2 support
uint64_t get_tsc()
{
    uint64_t a, d;
    asm volatile("rdtsc" : "=a"(a), "=d"(d));
    return (d << 32) | a;
}


int getFreq(void) {
    unsigned int eax, ebx, ecx, edx;
    int res;
    res = __get_cpuid(0x16, &eax, &ebx, &ecx, &edx);
    if (res == 0) {
        return 0;
    }
    return eax;
}


//int rdrand_16(uint16_t* x, int retry) {
//    return 0;
//}
//uint64_t get_tsc()
//{
//    return 0;
//}
//int getFreq(void) {
//    return 0;
//}

