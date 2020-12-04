all:
	python dec.py debugmenot.bin 2>/dev/null
	sed -i.bak "1 s/.*//" debugmenot.bin.decompiler2.c
	echo "#include<sys/types.h>\nint memcmp(const void *s1, const void *s2, size_t n)" > debugmenot.bin.decompiler3.c
	cat debugmenot.bin.decompiler2.c >> debugmenot.bin.decompiler3.c
	gcc -shared -fPIC debugmenot.bin.decompiler3.c -o memcmp.so
	ltrace ./debugmenot.bin 2>/dev/null | grep "ldhook"
	LD_PRELOAD=./memcmp.so ./debugmenot.bin 2>/dev/null | grep "ldhook"
