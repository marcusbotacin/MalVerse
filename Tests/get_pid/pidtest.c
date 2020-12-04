#include <sys/types.h>
#include <unistd.h>
#include<stdio.h>

int main()
{
	if(getpid()==0x1337)
	{
		printf("It was hidden!\n");
	}
	return 0;
}
