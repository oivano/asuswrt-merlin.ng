include ../common.mak

CFLAGS += -fPIC -Wall -Os
LDFLAGS += -shared

all: libbwdpi.so

libbwdpi.so: bwdpi_stub.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

install: all
	install -D libbwdpi.so $(INSTALLDIR)/usr/lib/libbwdpi.so
	$(STRIP) $(INSTALLDIR)/usr/lib/libbwdpi.so

clean:
	rm -f libbwdpi.so *.o

.PHONY: all install clean
