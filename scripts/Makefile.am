QPROGRAM := $(prefix)/bin/blackhole
QSPOOL_DIR := $(BH_SPOOL_DIR)/msg

DEFINES := -DQPROGRAM=\"$(QPROGRAM)\"


EXTRA_DIST = Makefile-no-automake \
	bad_word_list \
	bhconf bhedit \
	bhinstall \
	bhtest \
	blackhole_table.sql \
	indent.sh \
	insert.sql \
	parse_assassin_rules.pl \
	parse_bad_wordlist.pl \
	qmail-queue.c \
	qmail-queue.sh \
	spam \
	virus \
	sophos_update_ides.sh

all: qmail-queue

qmail-queue: qmail-queue.c
	$(CC) $(CFLAGS) $(OPT) $(DEFINES) -o qmail-queue qmail-queue.c
	strip qmail-queue

queue-install:
	cat ../etc/dot-blackhole.temp | sed -e s/LEVEL/7/g > $(QUEUE_CONFIG)
	@if [ ! -f "/var/qmail/qmail-queue-old" ]; then \
		cp -pa /var/qmail/bin/qmail-queue /var/qmail/bin/qmail-queue-old; \
		cp -pa /var/qmail/bin/qmail-queue /var/qmail/bin/qmail-queue-backup; \
	fi
	cp -fap qmail-queue /var/qmail/bin/qmail-queue-new

queue-replace:
	cp -fap /var/qmail/bin/qmail-queue-new /var/qmail/bin/qmail-queue

queue-undo:
	 cp -fap /var/qmail/bin/qmail-queue-old /var/qmail/bin/qmail-queue
	 rm -f /var/qmail/bin/qmail-queue-old

queue-clean:
	rm -f qmail-queue

install:
	echo 

clean-local: queue-clean

