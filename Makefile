CFLAGS=-Wall -g -O2

onionsearch: src/keys.c
	gcc $(CFLAGS) src/keys.c -o onionsearch -lcrypto

clean:
	rm -f onionsearch