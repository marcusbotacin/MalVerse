all:
	gcc cwd.c -o cwd.bin
	python dec.py cwd.bin 2>/dev/null | indent > cwd_patch.c
	cat cwd.bin.decompiler.c	
	cat cwd_patch.c
	gcc cwd_patch.c -shared -fPIC -o cwd_patch.so
	./cwd.bin
	LD_PRELOAD=./cwd_patch.so ./cwd.bin
