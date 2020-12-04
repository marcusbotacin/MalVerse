int ptrace(unsigned int var0, unsigned int var1, unsigned int var2, unsigned int var3)
{
    void angr_global_var;

    angr_global_var = 0;
    angr_global_var = angr_global_var + 1;
    if (angr_global_var == 1)
    {
        return 0x0;
    }
    if (angr_global_var == 2)
    {
        return -0x1;
    }
}
