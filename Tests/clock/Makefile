all:
	cat clock.c
	gcc clock.c -o clock
	cat sleep_patch.c
	gcc sleep_patch.c -shared -fPIC -o sleep.so
	python dec.py clock.bin 2>/dev/null
	cat sleep_patch_basis > sleep_patch2.c
	tail -10 clock.bin.decompiler2.c >> sleep_patch2.c
	cat sleep_patch2.c
	gcc sleep_patch2.c -shared -fPIC -o sleep2.so
	time -p ./clock
	LD_PRELOAD=./sleep.so time -p ./clock
	LD_PRELOAD=./sleep2.so time -p ./clock
