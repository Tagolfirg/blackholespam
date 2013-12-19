ifdef DEBUG
CFLAGS=-O0 -g -DDEBUG
else
CFLAGS:=$(CFLAGS)
STRIP=-s
endif
CFLAGS+= -Wall

ifndef PREFIX
PREFIX=/usr/local
endif

spamcomplain : spamcomplain.c
	gcc $(CFLAGS) -o $@ spamcomplain.c -lresolv

install : spamcomplain
	-mkdir $(PREFIX)/bin
	-mkdir $(PREFIX)/man
	-mkdir $(PREFIX)/man/man1
	install $(STRIP) -m 755 -o root -g bin spamcomplain $(PREFIX)/bin
	install -m 644 -o root -g root spamcomplain.1 $(PREFIX)/man/man1

tar :
	tar -C.. -cvzf spamcomplain.tgz --exclude '*.o' --exclude 'RCS' --exclude spamcomplain --exclude spamcomplain.tgz spamcomplain

clean :
	rm spamcomplain
	rm spamcomplain.tgz

