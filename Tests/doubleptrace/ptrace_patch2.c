#include<sys/types.h>
static int angr_global_var = 0;
long ptrace(int request, pid_t pid, void *addr, void *data)
{
    angr_global_var = angr_global_var + 1;
    if (angr_global_var == 1)
    {
        return 0;
    }
    if (angr_global_var == 2)
    {
        return -1;
    }
}
