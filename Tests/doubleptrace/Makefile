all:
	tail -9 ptrace.c
	gcc ptrace.c -o ptrace.bin
	cat ptrace_patch.c
	gcc -shared -fPIC ptrace_patch.c -o ptrace.so
	strace ./ptrace.bin 2>/dev/null
	LD_PRELOAD=./ptrace.so strace ./ptrace.bin 2>/dev/null
	python dec.py ptrace2.bin
	LD_PRELOAD=./ptrace2.so ./ptrace.bin
