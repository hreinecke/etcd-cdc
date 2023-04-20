
PRG = etcd_cdc
TEST = etcd_tool
DISC = etcd_discovery
PRG_OBJS = etcd_cdc.o nvmet_inotify.o nvmet_etcd.o
TEST_OBJS = etcd_tool.o nvmet_etcd.o
DISC_OBJS = etcd_discovery.o nvmet_etcd.o
CFLAGS = -Wall -g -Ilibb64/include -Ilibnvme/src
B64 = libb64/src/libb64.a
LIBNVME = libnvme/src/libnvme.a
LIBS = $(B64) -ljson-c -lcurl -luuid

all:	$(PRG) $(TEST) $(DISC)

$(B64):
	(cd libb64; make)

libnvme/config-host.h: libnvme/configure
	(cd libnvme; configure --disable-systems)
$(LIBNVME): libnvme/config-host.h
	(cd libnvme; make)

$(PRG): $(PRG_OBJS) $(B64)
	$(CC) $(CFLAGS) -o $(PRG) $^ $(LIBS)

$(TEST): $(TEST_OBJS) $(B64)
	$(CC) $(CFLAGS) -o $(TEST) $^ $(LIBS)

$(DISC): $(DISC_OBJS) $(B64) $(LIBNVME)
	$(CC) $(CFLAGS) -o $(DISC) $^ $(LIBNVME) $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $?

clean-b64:
	(cd libb64; make clean)

clean: clean-b64
	$(RM) $(TEST_OBJS) $(PRG_OBJS) $(DISC_OBJS) $(PRG) $(TEST) $(DISC)
