include ../common.mak

ifneq ($(BUILD_NAME),DSL-AC68U)
$(error Skynet is supported only for DSL-AC68U)
endif

CFLAGS += -std=gnu99 -Os -Wall -Wextra -ffunction-sections -fdata-sections $(EXTRACFLAGS)
CPPFLAGS += -I$(SRCBASE)/include -I../curl/include -I../sqlite -I../ipset-7.6/include
LDFLAGS += $(EXTRALDFLAGS) -Wl,--gc-sections
LDFLAGS += -Wl,-rpath-link,$(STAGEDIR)/usr/lib
LDLIBS += -L../curl/lib/.libs -lcurl -L../sqlite/.libs -lsqlite3
LDLIBS += -L../ipset-7.6/lib/.libs -lipset -L$(TOP_PLATFORM)/nvram$(BCMEX)$(EX7) -lnvram -lrt
LDLIBS += -L$(TOP)/shared -lshared

OBJECTS = main.o core.o store.o feeds.o backend.o schedule.o
LIBRARIES = ../curl/lib/.libs/libcurl.so ../sqlite/.libs/libsqlite3.so ../ipset-7.6/lib/.libs/libipset.so
LIBRARIES += $(TOP_PLATFORM)/nvram$(BCMEX)$(EX7)/libnvram.so $(TOP)/shared/libshared.so
CHECKFLAGS = -std=gnu99 -Wall -Wextra -Werror -fsanitize=address,undefined

all: skynet

skynet: $(OBJECTS) $(LIBRARIES)
	$(CC) $(LDFLAGS) -o $@ $(OBJECTS) $(LDLIBS)

%.o: %.c skynet.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -MMD -MP -c -o $@ $<

check:
	mkdir -p .check
	$(HOSTCC) -std=gnu99 -w -fsanitize=address,undefined -c ../sqlite/sqlite3.c -o .check/sqlite3.o
	$(HOSTCC) $(CHECKFLAGS) -DSKYNET_TEST -ffunction-sections -fdata-sections -Wl,--gc-sections \
		-I../sqlite -I../curl/include core.c store.c feeds.c test-core.c .check/sqlite3.o -ldl -lpthread -o .check/test-core
	.check/test-core
	for source in $(OBJECTS:.o=.c); do \
		$(CC) -std=gnu99 -Wall -Wextra -Werror $(CPPFLAGS) -c $$source -o .check/$${source%.c}.o || exit 1; \
	done
	$(CC) -std=gnu99 -Wall -Werror=implicit-function-declaration -DRTCONFIG_SKYNET \
		-I../shared -I$(SRCBASE)/include -c ../rc/skynet.c -o .check/rc-skynet.o
	$(MAKE) -C ../www skynet-pages INSTALLDIR=$(CURDIR)/.check/ui RTCONFIG_SKYNET=y
	test -f .check/ui/www/Advanced_Skynet_Content.asp
	$(MAKE) -C ../www skynet-pages INSTALLDIR=$(CURDIR)/.check/ui RTCONFIG_SKYNET=n
	test ! -e .check/ui/www/Advanced_Skynet_Content.asp

clean:
	rm -f skynet $(OBJECTS) $(OBJECTS:.o=.d)
	rm -rf .check

ifeq (,$(filter clean,$(MAKECMDGOALS)))
-include $(OBJECTS:.o=.d)
endif

.PHONY: all check clean