all:
	gcc diff.c -o diff.bin
	python diff.py diff.bin 2>/dev/null
	gcc diff2.c -o diff2.bin
	python diff.py diff2.bin 2>/dev/null
	gcc diff3.c -o diff3.bin
	python diff.py diff3.bin 2>/dev/null
