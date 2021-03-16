
PRG = etcd_cdc
TEST = etcd_tool
PRG_OBJS = etcd_cdc.o nvmet_inotify.o nvmet_etcd.o
TEST_OBJS = etcd_tool.o nvmet_etcd.o
CFLAGS = -Wall -g -Ilibb64/include
B64 = libb64/src/libb64.a
LIBS = $(B64) -ljson-c -lcurl

all:	$(B64) $(PRG) $(TEST)

$(B64):
	(cd libb64; make)

$(PRG): $(PRG_OBJS)
	$(CC) $(CFLAGS) -o $(PRG) $^ $(LIBS)

$(TEST): $(TEST_OBJS)
	$(CC) $(CFLAGS) -o $(TEST) $^ $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $?

clean-b64:
	(cd libb64; make clean)

clean: clean-b64
	$(RM) $(TEST_OBJS) $(PRG_OBJS) $(PRG) $(TEST)
