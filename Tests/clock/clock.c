#include<time.h>
#include<stdio.h>
#include<unistd.h>

#define SLEEP_TIME 10
#define SLEEP_CLOCKS 10

void mal()
{
	printf("malware\n");
}

void good()
{
	printf("goodware\n");
}

int main()
{
	clock_t t0 = clock();
	sleep(SLEEP_TIME);
	clock_t t1 = clock();
	if((t1-t0)>SLEEP_CLOCKS)
	{
		mal();
	}else{
		good();
	}
	return 0;
}
