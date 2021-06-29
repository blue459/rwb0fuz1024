targets: rwb0fuz1024.pdf rwb0fuz1024.o rwtest

rwb0fuz1024.pdf: rwb0fuz1024.w
	cweave rwb0fuz1024.w
	pdftex rwb0fuz1024.tex

rwb0fuz1024.c: rwb0fuz1024.w
	ctangle rwb0fuz1024.w

rwb0fuz1024.o: rwb0fuz1024.c
	gcc -Wall -c rwb0fuz1024.c -std=c99 -O2

rabin.o: rabin.c api.h
	gcc -Wall -c rabin.c -std=c99 -O2

rwtest: rabin.o rwtest.c devurandom.c api.h
	gcc -o rwtest -Wall -O2 rwtest.c devurandom.c rabin.o  -lgmp -lcrypto

