all:
	gcc pidtest.c -o pidtest.bin
	python dec.py pidtest.bin
	cat pidtest.bin.decompiler1.c
	cat pidtest.bin.decompiler2.c
	gcc -shared -fPIC pidtest.bin.decompiler2.c -o pidtest.so
	ltrace ./pidtest.bin >/dev/null
	LD_PRELOAD=./pidtest.so ltrace ./pidtest.bin >/dev/null
