
PRG = nvmet_etcd
TEST = etcd_tool
PRG_OBJS = nvmet_etcd.o nvmet_inotify.o etcd_client.o
TEST_OBJS = etcd_tool.o etcd_client.o
CFLAGS = -Wall -g -Ilibb64/include
B64 = libb64/src/libb64.a
LIBS = -ljson-c -lcurl -luuid

all:	$(PRG) $(TEST)

$(B64):
	(cd libb64; make)

$(PRG): $(PRG_OBJS) $(B64)
	$(CC) $(CFLAGS) -o $(PRG) $^ $(LIBS)

$(TEST): $(TEST_OBJS) $(B64)
	$(CC) $(CFLAGS) -o $(TEST) $^ $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $?

clean-b64:
	(cd libb64; make clean)

clean: clean-b64
	$(RM) $(TEST_OBJS) $(PRG_OBJS) $(DISC_OBJS) $(PRG) $(TEST) $(DISC)

nvmet_etcd.c: nvmet_etcd.h
etcd_tool.c: nvmet_etcd.h
nvmet_inotiry.c: nvmet_etcd.h list.h
etcd_client: nvmet_etcd.h
