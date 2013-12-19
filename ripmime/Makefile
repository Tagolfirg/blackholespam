
all: mimelib

clean:
	$(MAKE) -f Makefile.orig clean
	rm -f *.[ao]

mimelib:
	$(MAKE) -f Makefile.orig mimelib

ripmime.a: mimelib

ripmime: mimelib

install:
	$(MAKE) -f Makefile.orig install

