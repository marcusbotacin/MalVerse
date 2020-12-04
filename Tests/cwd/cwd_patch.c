#include <unistd.h>
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
static void init (void) __attribute__ ((constructor));
#define STR "BOMB"
void *addr;
static void
init (void)
{
  addr = (char *) malloc (100);
  strcpy (addr, STR);
}

char *
getcwd (char *buf, size_t size)
{
  return addr;
}
