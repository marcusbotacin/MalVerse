#include<stdio.h>
#include<time.h>
		
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
	if(time(NULL)==0x1337)
	{
		mal();
	}else{
		good();
	}
	return 0;
}
