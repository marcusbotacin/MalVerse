all:
	gcc time.c -o time.bin
	python dec.py time.bin
	cat time.bin.decompiler1.c
	cat time.bin.decompiler2.c
	sed -i.bak "1 s/.*//" time.bin.decompiler2.c
	echo "#include <time.h>\ntime_t time(time_t *tloc)" > time.bin.decompiler3.c
	cat time.bin.decompiler2.c >> time.bin.decompiler3.c
	gcc -shared -fPIC time.bin.decompiler3.c -o time.so
	./time.bin
	LD_PRELOAD=./time.so ./time.bin
