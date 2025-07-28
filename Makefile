CC = gcc
CFLAGS = -std=c99 -Wall -Wextra -Wvla -O3 -flto -fno-strict-aliasing -ffunction-sections -fdata-sections -DNDEBUG
LDFLAGS = -O3 -flto -fno-strict-aliasing -Wl,--gc-sections -s
LIBS = -lm -lssl -lcrypto
SRCS = dns2tcp-plus.c libev/ev.c
OBJS = $(SRCS:.c=.o)
MAIN = dns2tcp-plus
DESTDIR = /usr/local/bin

.PHONY: all install clean

all: $(MAIN)

install: $(MAIN)
	mkdir -p $(DESTDIR)
	install -m 0755 $(MAIN) $(DESTDIR)

clean:
	$(RM) $(MAIN) *.o libev/*.o

$(MAIN): $(OBJS)
	$(CC) $(LDFLAGS) -o $(MAIN) $(OBJS) $(LIBS)

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@
