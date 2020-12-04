#include<time.h>

unsigned int sleep(unsigned int seconds)
{
	return 0;
}


int angr_global_var = 0;
clock_t clock(void)
{
    angr_global_var = angr_global_var + 1;
    if (angr_global_var == 1)
    {
        return 0x0;
    }
    if (angr_global_var == 2)
    {
        return 0xb;
    }
}
