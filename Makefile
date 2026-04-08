
FUSE = nvmetd_fuse
INOTIFY = nvmetd_inotify
WATCHER = nvmetd_etcd
CLIENT_OBJS = etcd/backend.o etcd/watcher.o etcd/client.o etcd/neon.o etcd/base64.o
FUSE_OBJS = nvmetd_fuse.o fuse_etcd.o $(CLIENT_OBJS)
INOTIFY_OBJS = nvmetd_inotify.o configfs.o inotify.o $(CLIENT_OBJS)
WATCHER_OBJS = nvmetd_etcd.o configfs.o $(CLIENT_OBJS)

CFLAGS = -Wall -g -I. -I/usr/include/fuse3
LIBS = -ljson-c -luuid -lneon

all:	$(FUSE) $(INOTIFY) $(WATCHER)

$(FUSE): $(FUSE_OBJS)
	$(CC) $(CFLAGS) -o $(FUSE) $^ $(LIBS) -lpthread -lfuse3

$(INOTIFY): $(INOTIFY_OBJS)
	$(CC) $(CFLAGS) -o $(INOTIFY) $^ $(LIBS) -lpthread

$(WATCHER): $(WATCHER_OBJS)
	$(CC) $(CFLAGS) -o $(WATCHER) $^ $(LIBS) -lpthread

firmware.h: gen_firmware_rev.sh
	bash ./$< $@

clean:
	$(RM) firmware.h *.o $(DAEMON_OBJS) $(NVMETD_OBJS) $(DAEMON) $(NVMETD)

daemon.o: daemon.c common.h nvme.h etcd/client.h etcd/backend.h
nvmetd.o: nvmetd.c nvmetd.h etcd/client.h
inotify.o: inotify.c common.h configfs.h etcd/client.h etcd/backend.h nvmetd.h
configfs.o: configfs.c common.h configfs.h etcd/client.h etcd/backend.h
fuse_etcd.o: fuse_etcd.c common.h nvme.h etcd/client.h etcd/backend.h
etcd/backend.o: etcd/backend.c common.h nvme.h firmware.h etcd/client.h etcd/backend.h
etcd/client.o: etcd/client.c common.h etcd/client.h etcd/base64.h
