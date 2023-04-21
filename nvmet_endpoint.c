#define _GNU_SOURCE
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include <sys/poll.h>

#include "nvmet_common.h"
#include "nvmet_endpoint.h"
#include "nvmet_tcp.h"

void disconnect_endpoint(struct endpoint *ep, int shutdown)
{
	struct ctrl_conn *ctrl = ep->ctrl;

	tcp_destroy_endpoint(ep);

	ep->state = DISCONNECTED;

	if (ctrl) {
		struct subsystem *subsys = ctrl->subsys;

		pthread_mutex_lock(&subsys->ctrl_mutex);
		ctrl->num_endpoints--;
		ep->ctrl = NULL;
		if (!ctrl->num_endpoints) {
			printf("ctrl %d: deleting controller",
			       ctrl->cntlid);
			list_del(&ctrl->node);
			free(ctrl);
		}
		pthread_mutex_unlock(&subsys->ctrl_mutex);
	}
}

int endpoint_update_qdepth(struct endpoint *ep, int qsize)
{
	struct ep_qe *qes;
	int i;

	if (qsize + 1 == ep->qsize)
		return 0;

	qes = calloc(qsize + 1, sizeof(struct ep_qe));
	if (!qes)
		return -1;
	free(ep->qes);
	ep->qes = qes;
	for (i = 0; i <= qsize; i++) {
		ep->qes[i].tag = i;
		ep->qes[i].ep = ep;
	}
	ep->qsize = qsize + 1;
	return 0;
}

static struct io_uring_sqe *endpoint_submit_poll(struct endpoint *ep,
						 int poll_flags)
{
	struct io_uring_sqe *sqe;
	int ret;

	sqe = io_uring_get_sqe(&ep->uring);
	if (!sqe) {
		fprintf(stderr, "endpoint %d: failed to get poll sqe", ep->qid);
		return NULL;
	}

	io_uring_prep_poll_add(sqe, ep->sockfd, poll_flags);
	io_uring_sqe_set_data(sqe, sqe);

	ret = io_uring_submit(&ep->uring);
	if (ret <= 0) {
		fprintf(stderr, "endpoint %d: submit poll sqe failed, error %d",
			ep->qid, ret);
		return NULL;
	}
	return sqe;
}

void *endpoint_thread(void *arg)
{
	struct endpoint *ep = arg;
	struct io_uring_sqe *pollin_sqe = NULL;
	sigset_t set;
	int ret;

	sigemptyset(&set);
	sigaddset(&set, SIGPIPE);
	pthread_sigmask(SIG_BLOCK, &set, NULL);

	ret = io_uring_queue_init(32, &ep->uring, 0);
	if (ret) {
		fprintf(stderr, "endpoint %d: error %d creating uring",
			ep->qid, ret);
		goto out_disconnect;
	}

	while (!stopped) {
		struct io_uring_cqe *cqe;
		void *cqe_data;

		if (!pollin_sqe) {
			pollin_sqe = endpoint_submit_poll(ep, POLLIN);
			if (!pollin_sqe)
				break;
		}

		ret = io_uring_wait_cqe(&ep->uring, &cqe);
		if (ret < 0) {
			fprintf(stderr, "ctrl %d qid %d wait cqe error %d",
				ep->ctrl ? ep->ctrl->cntlid : -1,
				  ep->qid, ret);
			break;
		}
		io_uring_cqe_seen(&ep->uring, cqe);
		cqe_data = io_uring_cqe_get_data(cqe);
		if (cqe_data == pollin_sqe) {
			ret = cqe->res;
			if (ret < 0) {
				fprintf(stderr, "ctrl %d qid %d poll error %d",
					ep->ctrl ? ep->ctrl->cntlid : -1,
					ep->qid, ret);
				break;
			}
			if (ret & POLLERR) {
				ret = -ENODATA;
				printf("ctrl %d qid %d poll conn closed",
				       ep->ctrl ? ep->ctrl->cntlid : -1,
				       ep->qid);
				break;
			}
			pollin_sqe = NULL;
			if (ep->recv_state == RECV_PDU) {
				ret = tcp_read_msg(ep);
			}
			if (!ret && ep->recv_state == HANDLE_PDU) {
				ret = tcp_handle_msg(ep);
				if (!ret) {
					ep->recv_pdu_len = 0;
					ep->recv_state = RECV_PDU;
				}
			}
			if (!ret || ret == -EAGAIN) {
				if (ep->ctrl)
					ep->kato_countdown = ep->ctrl->kato;
				else
					ep->kato_countdown = RETRY_COUNT;
			}

		} else {
			struct ep_qe *qe = cqe_data;
			if (!qe) {
				fprintf(stderr, "ctrl %d qid %d empty cqe",
					ep->ctrl ? ep->ctrl->cntlid : -1,
					ep->qid);
				ret = -EAGAIN;
			}
			ret = handle_data(ep, qe, cqe->res);
		}
		if (ret == -EAGAIN)
			if (--ep->kato_countdown > 0)
				continue;
		/*
		 * ->read_msg returns -ENODATA when the connection
		 * is closed; that shouldn't count as an error.
		 */
		if (ret == -ENODATA) {
			printf("ctrl %d qid %d connection closed",
			       ep->ctrl ? ep->ctrl->cntlid : -1,
			       ep->qid);
			break;
		}
		if (ret < 0) {
			fprintf(stderr, "ctrl %d qid %d error %d retry %d",
				ep->ctrl ? ep->ctrl->cntlid : -1,
				ep->qid, ret, ep->kato_countdown);
			break;
		}
	}
	io_uring_queue_exit(&ep->uring);

out_disconnect:
	disconnect_endpoint(ep, !stopped);

	printf("ctrl %d qid %d %s",
	       ep->ctrl ? ep->ctrl->cntlid : -1, ep->qid,
	       stopped ? "stopped" : "disconnected");
	pthread_exit(NULL);

	return NULL;
}

int run_endpoint(struct endpoint *ep, int id)
{
	int			 ret;

	ret = tcp_create_endpoint(ep, id);
	if (ret) {
		fprintf(stderr, "Failed to create endpoint %d error %d",
			id, ret);
		return ret;
	}

retry:
	ret = tcp_accept_connection(ep);
	if (ret) {
		if (ret == -EAGAIN)
			goto retry;

		fprintf(stderr, "ep %d: accept failed error %d",
			id, ret);
		return ret;
	}

	ep->state = CONNECTED;
	return 0;
}

struct endpoint *enqueue_endpoint(int id, struct host_iface *iface)
{
	struct endpoint		*ep;
	int			 ret;

	ep = malloc(sizeof(struct endpoint));
	if (!ep) {
		fprintf(stderr, "no memory");
		close(id);
		return NULL;
	}

	memset(ep, 0, sizeof(struct endpoint));

	ep->iface = iface;
	ep->kato_countdown = RETRY_COUNT;
	ep->kato_interval = KATO_INTERVAL;
	ep->maxh2cdata = 0x10000;
	ep->qid = -1;
	ep->recv_state = RECV_PDU;

	ret = run_endpoint(ep, id);
	if (ret) {
		fprintf(stderr, "run_endpoint failed with %d", ret);
		goto out;
	}

	pthread_mutex_lock(&iface->ep_mutex);
	list_add(&ep->node, &iface->ep_list);
	pthread_mutex_unlock(&iface->ep_mutex);
	return ep;
out:
	free(ep);
	close(id);
	return NULL;
}
