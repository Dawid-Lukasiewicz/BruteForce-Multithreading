all: zad1.c
	gcc -o zad1 zad1.c -lssl -lcrypto -pthread

run: all
	./zad1

clean:
	rm zad1