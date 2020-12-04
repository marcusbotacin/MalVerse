#include <unistd.h>
#include<stdio.h>
#include<sys/ptrace.h>
#include<signal.h>
#include<stdlib.h>
#include<sys/wait.h>

void fool()
{
	printf("You are fooling me!\n");
}

void ok()
{
	printf("Malicious Here!\n");
}

int main()
{
	if(ptrace(PTRACE_TRACEME)==-1)
	{
		fool();
	}else if(ptrace(PTRACE_TRACEME)==0){
		fool();
	}else{
		ok();
	}
	return 0;
}
