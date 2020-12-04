#include<stdio.h>
#include<string.h>
#include<stdlib.h>
int main()
{
	int a;
	char str[100];
	scanf("%s",str);
	if(strcmp(str,"foo")==0 || memcmp(str,"foo",3)==0)
	{
		a = strlen(str);
	}else{
		a = 0;	
	}
	printf("%ld\n",a*strlen(str));
	return 0;
}
