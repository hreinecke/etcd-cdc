
DAEMON = daemon
NVMETD = nvmetd
CLIENT_OBJS = etcd/client.o etcd/neon.o etcd/base64.o
DAEMON_OBJS = daemon.o configfs.o fuse_etcd.o etcd/backend.o etcd/watcher.o $(CLIENT_OBJS)
NVMETD_OBJS = nvmetd.o $(CLIENT_OBJS)
CFLAGS = -Wall -g -I. -I/usr/include/fuse3
LIBS = -ljson-c -luuid -lneon

all:	$(DAEMON) $(NVMETD)

$(DAEMON): $(DAEMON_OBJS)
	$(CC) $(CFLAGS) -o $(DAEMON) $^ $(LIBS) -lpthread -lfuse3

$(NVMETD): $(NVMETD_OBJS)
	$(CC) $(CFLAGS) -o $(NVMETD) $^ $(LIBS) -lpthread

$(TEST): $(TEST_OBJS)
	$(CC) $(CFLAGS) -o $(TEST) $^ $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $?

firmware.h: gen_firmware_rev.sh
	bash ./$< $@

clean:
	$(RM) firmware.h *.o $(DAEMON_OBJS) $(NVMETD_OBJS) $(DAEMON) $(NVMETD)

daemon.c: common.h nvme.h etcd/client.h etcd/backend.h
nvmetd.c: nvmetd.h etcd/client.h
configfs.c: common.h configfs.h utils.h etcd/client.h etcd/backend.h
etcd/backend.c: common.h nvme.h firmware.h etcd/client.h etcd/backend.h

