all:
	gcc ptrace.c -o ptrace.bin
	python dec.py ptrace.bin
	cat ptrace.bin.decompiler1.c
	cat ptrace.bin.decompiler2.c
	sed -i.bak "1 s/.*//" ptrace.bin.decompiler2.c
	echo "#include<sys/types.h>\nlong ptrace(int request, pid_t pid, void *addr, void *data)" > ptrace.bin.decompiler3.c
	cat ptrace.bin.decompiler2.c >> ptrace.bin.decompiler3.c
	gcc -shared -fPIC ptrace.bin.decompiler3.c -o ptrace.so
	./ptrace.bin
	LD_PRELOAD=./ptrace.so ./ptrace.bin
