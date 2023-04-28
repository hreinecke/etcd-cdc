#ifndef __COMMON_H__
#define __COMMON_H__

#define unlikely __glibc_unlikely

#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <uuid/uuid.h>

#include "types.h"
#include "list.h"
#include "nvme.h"
#include "nvme_tcp.h"
#include "etcd_client.h"

extern int			 debug;
extern char			*hostnqn;
extern struct list_head		devices;
extern struct list_head		interfaces;

#define NVMF_UUID_FMT		"nqn.2014-08.org.nvmexpress:uuid:%s"

#define NVMF_DQ_DEPTH		2
#define NVMF_SQ_DEPTH		128
#define NVMF_NUM_QUEUES		8

#define MAX_NQN_SIZE		256
#define MAX_ALIAS_SIZE		64

#define PAGE_SIZE		4096

#define KATO_INTERVAL	1000	/* in ms as per spec */
#define RETRY_COUNT	120	/* 2 min; value is multiplied with kato interval */


#define ADRFAM_STR_IPV4 "ipv4"
#define ADRFAM_STR_IPV6 "ipv6"

#define IPV4_LEN		4
#define IPV4_OFFSET		4
#define IPV4_DELIM		"."

#define IPV6_LEN		8
#define IPV6_OFFSET		8
#define IPV6_DELIM		":"

enum { DISCONNECTED, CONNECTED };

extern int stopped;

struct ep_qe {
	struct list_head node;
	int tag;
	struct endpoint *ep;
	struct nsdev *ns;
	union nvme_tcp_pdu pdu;
	struct iovec iovec;
	struct nvme_completion resp;
	void *data;
	u64 data_len;
	u64 data_pos;
	u64 data_remaining;
	u64 iovec_offset;
	int ccid;
	int opcode;
	bool busy;
};

enum { RECV_PDU, RECV_DATA, HANDLE_PDU };

struct endpoint {
	struct list_head node;
	pthread_t pthread;
	struct etcd_cdc_ctx *ctx;
	struct host_iface *iface;
	struct ctrl_conn *ctrl;
	struct ep_qe *qes;
	union nvme_tcp_pdu *recv_pdu;
	int recv_pdu_len;
	union nvme_tcp_pdu *send_pdu;
	int recv_state;
	int qsize;
	int state;
	int qid;
	int kato_countdown;
	int kato_interval;
	int sockfd;
	int maxr2t;
	int maxh2cdata;
	int mdts;
};

struct ctrl_conn {
	struct list_head node;
	char nqn[MAX_NQN_SIZE + 1];
	int cntlid;
	int ctrl_type;
	int kato;
	int num_endpoints;
	int max_endpoints;
	int aen_mask;
	u64 csts;
	u64 cc;
};

struct nsdev {
	struct list_head node;
	struct ns_ops *ops;
	int nsid;
	int fd;
	size_t size;
	unsigned int blksize;
	uuid_t uuid;
};

struct host_iface {
	struct list_head node;
	pthread_t pthread;
	struct etcd_cdc_ctx *ctx;
	struct list_head ep_list;
	pthread_mutex_t ep_mutex;
	char address[41];
	int port_num;
	int adrfam;
	int portid;
	int listenfd;
	unsigned char *tls_key;
	size_t tls_key_len;
};

extern int tcp_debug;
extern char *discovery_nqn;
extern struct list_head subsys_linked_list;
extern struct list_head iface_linked_list;

static inline void set_response(struct nvme_completion *resp,
				__u16 ccid, __u16 status, bool dnr)
{
	if (!status)
		dnr = false;
	resp->command_id = ccid;
	resp->status = ((dnr ? NVME_SC_DNR : 0) | status) << 1;
}

#define ctrl_info(e, f, x...)					\
	do {							\
		printf("ctrl %d qid %d: " f "\n",		\
		       (e)->ctrl ? (e)->ctrl->cntlid : -1,	\
		       (e)->qid, ##x);				\
		fflush(stdout);					\
	} while (0)

#define ctrl_err(e, f, x...)					\
	do {							\
		fprintf(stderr, "ctrl %d qid %d: " f "\n",	\
		       (e)->ctrl ? (e)->ctrl->cntlid : -1,	\
		       (e)->qid, ##x);				\
		fflush(stderr);					\
	} while (0)

#define ep_info(e, f, x...)					\
	do {							\
		printf("ep %d: " f "\n",			\
		       (e)->sockfd, ##x);			\
		fflush(stdout);					\
	} while (0)

#define ep_err(e, f, x...)					\
	do {							\
		fprintf(stderr, "ep %d: " f "\n",		\
			(e)->sockfd, ##x);			\
		fflush(stderr);					\
	} while (0)


void nvmet_etcd_set_genctr(struct etcd_cdc_ctx *ctx, int genctr);
int nvmet_etcd_get_genctr(struct etcd_cdc_ctx *ctx);
void nvmet_etcd_discovery_nqn(struct etcd_cdc_ctx *ctx);

void handle_disconnect(struct endpoint *ep, int shutdown);
int handle_request(struct endpoint *ep, struct nvme_command *cmd);
int handle_data(struct endpoint *ep, struct ep_qe *qe, int res);
void *run_host_interface(void *arg);
void terminate_interfaces(struct host_iface *iface, int signo);
int endpoint_update_qdepth(struct endpoint *ep, int qsize);

u8 *nvmet_etcd_disc_log(struct etcd_cdc_ctx *ctx, char *hostnqn, size_t *len);

#endif
