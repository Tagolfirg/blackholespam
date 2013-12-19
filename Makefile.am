## Process this file with automake to create Makefile.in
AUTOMAKE_OPTIONS = no-dependencies

## This is for using the Sophos SDK, you need a license and the scanner,
SOPHOS_SRC = sophos.c
## This is for using the Trend Micro SDK, you need a license and the scanner,
TMICRO_SRC = tmicro.c

## Mysql support
SQL_SRC = sqlconfig.c

## SpamAssassin support
SPAMC_SRC = spamassassin.c

## LIB PCRE Includes, for RedHat 7.2
LIBPCRE_INCLUDES = -I/usr/include/pcre

#fix by David Ronis <ronis@montroll.chem.mcgill.ca>
SED_prefix=`echo $(prefix) | sed -e 's/\//\\\\\//g'`

SUBDIRS = scripts etc doc SMTP_DEMON ripmime

bin_PROGRAMS = blackhole 

blackhole_SOURCES =  blackhole.c virusscan.c rblcheck.c rbllookup.c ipcalc.c \
	regexip.c checkmyrelay.c checkbadrelay.c checkgoodrelay.c \
	checkbademail.c checkgoodemail.c checkbody.c checkmyemail.c \
	checkdns.c logging.c checkcharset.c expire.c checkreverse.c \
	checkascii128.c razorcheck.c checkexcluded.c checkheader.c nocheck.c \
	checkctype.c checkencoding.c string.c snprintf.c qmail-qfilter.c \
	pyzorcheck.c execute.c checkattach.c \
	extract_tstamp.c mimeparse.c $(SQL_SRC) $(SOPHOS_SRC) $(TMICRO_SRC) $(SPAMC_SRC)

blackhole_LIBS := $(LIBS)

blackhole_LDADD := $(RIPMIME_LIBS) $(MYSQL_LIBS) $(SOPHOS_LIBS) $(TMICRO_LIBS)

INCLUDES := $(INCLUDES) $(LIBPCRE_INCLUDES) $(MYSQL_INCLUDES) $(SOPHOS_INCLUDES)

EXTRA_DIST = README QUEUE_INSTALL MCONFIG Setup Makefile-no-automake buildconf \
	blackhole.h  body_patterns.h  my_string.h max.h sophos.h virus.h \
	misc.h execute.h test_msg_spam test_msg_virus

OPT := -O2 ${OPT}

CFLAGS := $(CFLAGS) $(OPT)

CPPFLAGS = -DBH_EDIT_PROG=\"$(prefix)/bin/bhedit\"

strip: blackhole
	strip blackhole

install: setup

setup: blackhole
	sh ./INSTALL $(prefix)
	cp -f  blackhole $(prefix)/bin/blackhole
	chmod 755 $(prefix)/bin/blackhole
	chown root $(prefix)/bin/blackhole
	strip $(prefix)/bin/blackhole
	cp -f doc/*.1 $(prefix)/man/man1/
	cp -f doc/*.5 $(prefix)/man/man5/
	cp -f doc/*.sgml $(prefix)/doc/
	cat scripts/bhconf | \
		sed -e s/BASEMAILDIR/$(MAIL_DIR)/g | \
		sed -e s/BASEPREFIX/$(SED_prefix)/g \
	> $(prefix)/bin/bhconf

	cat scripts/bhedit | \
		sed -e s/BASEMAILDIR/$(MAIL_DIR)/g | \
		sed -e s/BASEPREFIX/$(SED_prefix)/g \
	> $(prefix)/bin/bhedit

	cat scripts/bhinstall | \
		sed -e s/BASEMAILDIR/$(MAIL_DIR)/g | \
		sed -e s/BASEPREFIX/$(SED_prefix)/g \
	> $(prefix)/bin/bhinstall

	cat scripts/bhtest | \
		sed -e s/BASEMAILDIR/$(MAIL_DIR)/g | \
		sed -e s/BASEPREFIX/$(SED_prefix)/g \
	> $(prefix)/bin/bhtest

	chmod 755 $(prefix)/bin/bhconf
	chmod 755 $(prefix)/bin/bhedit
	chmod 755 $(prefix)/bin/bhinstall
	chmod 755 $(prefix)/bin/bhtest

	cp -f etc/dot-blackhole.temp \
		$(prefix)/share/blackhole/dot-blackhole.temp
	cp -f etc/dot-muttrc-spam \
		$(prefix)/share/blackhole/dot-muttrc-spam
	cp -f etc/dot-muttrc-virus \
		$(prefix)/share/blackhole/dot-muttrc-virus

	cat scripts/spam | \
		sed -e s/MAILDIR/$(MAIL_DIR)/g | \
		sed -e s/PREFIX/$(SED_prefix)/g > $(prefix)/bin/spam
	chmod 755 $(prefix)/bin/spam

	cat scripts/virus | \
		sed -e s/MAILDIR/$(MAIL_DIR)/g | \
		sed -e s/PREFIX/$(SED_prefix)/g > $(prefix)/bin/virus
	chmod 755 $(prefix)/bin/virus
        
install_queue:
	cat QUEUE_INSTALL|more

upgrade: all strip
	cp -f $(prefix)/bin/blackhole $(prefix)/bin/blackhole.old
	cp -f  blackhole $(prefix)/bin/blackhole
	chmod 755 $(prefix)/bin/blackhole
	chown root $(prefix)/bin/blackhole
	strip $(prefix)/bin/blackhole
	cp -f doc/*.1 $(prefix)/man/man1/
	cp -f doc/*.5 $(prefix)/man/man5/
	cp -f doc/*.sgml $(prefix)/doc/
	cat scripts/bhconf | \
		sed -e s/BASEMAILDIR/$(MAIL_DIR)/g | \
		sed -e s/BASEPREFIX/$(SED_prefix)/g \
	> $(prefix)/bin/bhconf

	cat scripts/bhedit | \
		sed -e s/BASEMAILDIR/$(MAIL_DIR)/g | \
		sed -e s/BASEPREFIX/$(SED_prefix)/g \
	> $(prefix)/bin/bhedit

	cat scripts/bhinstall | \
		sed -e s/BASEMAILDIR/$(MAIL_DIR)/g | \
		sed -e s/BASEPREFIX/$(SED_prefix)/g \
	> $(prefix)/bin/bhinstall

	cat scripts/bhtest | \
		sed -e s/BASEMAILDIR/$(MAIL_DIR)/g | \
		sed -e s/BASEPREFIX/$(SED_prefix)/g \
	> $(prefix)/bin/bhtest

	chmod 755 $(prefix)/bin/bhconf
	chmod 755 $(prefix)/bin/bhedit
	chmod 755 $(prefix)/bin/bhinstall
	chmod 755 $(prefix)/bin/bhtest

