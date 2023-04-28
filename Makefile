
PRG = nvmet_etcd
DISC = nvmet_discd
TEST = etcd_tool
DISC_OBJS = nvmet_daemon.o nvmet_tcp.o nvmet_cmds.o nvmet_endpoint.o nvmet_discovery.o etcd_client.o nvmet_lib.o
PRG_OBJS = nvmet_etcd.o nvmet_inotify.o etcd_client.o nvmet_lib.o
TEST_OBJS = etcd_tool.o etcd_client.o
CFLAGS = -Wall -g
B64 = base64.o
LIBS = -ljson-c -lcurl -luuid

all:	$(PRG) $(DISC) $(TEST)

$(B64): base64.c

$(PRG): $(PRG_OBJS) $(B64)
	$(CC) $(CFLAGS) -o $(PRG) $^ $(LIBS)

$(DISC): $(DISC_OBJS) $(B64)
	$(CC) $(CFLAGS) -o $(DISC) $^ $(LIBS) -lpthread

$(TEST): $(TEST_OBJS) $(B64)
	$(CC) $(CFLAGS) -o $(TEST) $^ $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $?

clean:
	$(RM) $(TEST_OBJS) $(PRG_OBJS) $(DISC_OBJS) $(PRG) $(TEST) $(DISC)

nvmet_etcd.c: etcd_client.h nvmet_etcd.h
etcd_tool.c: etcd_client.h nvmet_etcd.h
nvmet_inotify.c: etcd_client.h nvmet_etcd.h list.h
nvmet_discovery.c: nvmet_common.h nvmet_tcp.h
nvmet_cmds.c: nvmet_common.h nvmet_tcp.h
nvmet_daemon.c: nvmet_common.h nvmet_endpoint.h nvmet_tcp.h
nvmet_endpoint.c: nvmet_common.h nvmet_endpoint.h nvmet_tcp.h
nvmet_tcp.c: types.h nvme.h nvme_tcp.h nvmet_common.h nvmet_tcp.h
etcd_client.c: nvmet_etcd.h
