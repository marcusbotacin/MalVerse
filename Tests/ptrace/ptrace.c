#include <unistd.h>
#include<stdio.h>
#include<sys/ptrace.h>
#include<signal.h>
#include<stdlib.h>
#include<sys/wait.h>
int main()
{
	if(ptrace(PTRACE_TRACEME)==-1)
	{
		printf("This was Hidden!\n");
	}
	return 0;
}
