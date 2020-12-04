#include<stdio.h>
#include <unistd.h>
#include<string.h>

void mal()
{
	printf("malicious\n");
}

void good()
{
	printf("goodware\n");
}

int main()
{
       	if(strcmp(getcwd(NULL,0),"BOMB")==0)
	{
		mal();
	}else{
		good();
	}
	return 0;
}
