CFLAGS := -Wall -O2 $(CFLAGS)
#DB = -g

all: demon.c
	$(CC) $(CFLAGS) $(DB) -o demon demon.c
	strip demon

clean:
	rm -f demon *.o

install:
	echo "copy demon.init somewhere and startup by running it"
	echo "you probably want to edit it and change the default command"
	echo "line arguments"

