include ../common.mak

CFLAGS	= -Os -Wall $(EXTRACFLAGS) $(NETWORK_DAEMON_HARDEN_CFLAGS) $(STACK_PROTECTOR_ALL_CFLAGS) -fPIC
LIBS = 
ifeq ($(RTCONFIG_BCMARM),y)
ifeq ($(HND_ROUTER),y)
LDFLAGS	= $(NETWORK_DAEMON_HARDEN_LDFLAGS)
else
LDFLAGS	= $(NETWORK_DAEMON_HARDEN_LD_FLAGS)
endif
else
LDFLAGS	= $(NETWORK_DAEMON_HARDEN_LDFLAGS)
endif

CFLAGS	+= -I$(TOP)/openssl/include
LIBS += -L$(TOP)/openssl -lssl -lcrypto $(if $(RTCONFIG_OPENSSL11),-lpthread,)

ifneq ($(RTCONFIG_BCMARM),y)
LIBS += -lpthread
endif
OBJ = mssl.o

all: libmssl.so libmssl.a

libmssl.so: $(OBJ)
ifeq ($(RTCONFIG_BCMARM),y)
ifeq ($(HND_ROUTER),y)
	$(CC) $(LDFLAGS) -shared -o $@ $^ $(LIBS)
else
	$(LD) $(LDFLAGS) $(LIBS) -shared -o $@ $^
endif
else
	$(CC) $(LDFLAGS) -shared -o $@ $^ $(LIBS)
endif
	$(STRIP) $@
	$(CPTMP)

libmssl.a: $(OBJ)
	rm -f $@
	$(AR) cruv $@ $^

clean:
	rm -f .*.depend *.o *.so *.a

install: all
	@echo " [mssl] Installing..."
	install -D libmssl.so $(INSTALLDIR)/usr/lib/libmssl.so
ifneq ($(RTCONFIG_BCMARM),y)
	$(STRIP) $(INSTALLDIR)/usr/lib/libmssl.so
endif

%.o: %.c .%.depend
	@echo " [mssl] CC $@"
	@$(CC) $(CFLAGS) -c $<

.depend: $(OBJS:%.o=%.c)
	@$(CC) $(CFLAGS) -M $^ > .depend

.%.depend: %.c
	@$(CC) $(CFLAGS) -M $< > $@

ifeq (,$(filter clean,$(MAKECMDGOALS)))
-include $(OBJS:%.o=.%.depend)
endif
