#include<stdio.h>
#include<string.h>
#include<Windows.h>

int main()
{
	if(GetCurrentProcessId()==0x1337 || IsProcessorFeaturePresent(34)==TRUE)
	{
		printf("Malware\n");		
	}
	return 0;
}

