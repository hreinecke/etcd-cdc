#define _GNU_SOURCE
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include <sys/epoll.h>

#include "nvmet_common.h"
#include "nvmet_endpoint.h"
#include "nvmet_tcp.h"

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

void *endpoint_thread(void *arg)
{
	struct endpoint *ep = arg;
	int epollfd;
	struct epoll_event ev;
	sigset_t set;
	int ret;

	sigemptyset(&set);
	sigaddset(&set, SIGPIPE);
	pthread_sigmask(SIG_BLOCK, &set, NULL);

	epollfd = epoll_create(1);
	if (epollfd < 0) {
		ep_err(ep, "error %d creating epoll instance", errno);
		goto out_disconnect;
	}
	ev.events = EPOLLIN;
	ev.data.fd = ep->sockfd;
	if (epoll_ctl(epollfd, EPOLL_CTL_ADD, ep->sockfd, &ev) < 0) {
		ep_err(ep, "failed to add epoll fd, error %d", errno);
		goto out_close;
	}

	while (!stopped) {
		ret = epoll_wait(epollfd, &ev, 1, ep->kato_interval);
		if (ret == 0) {
			/* epoll timeout, refresh lease */
			ret = etcd_lease_keepalive(ep->ctx);
			/* And terminate on KATO */
			if (!--ep->kato_countdown) {
				ep_err(ep, "KATO timeout");
				break;
			}
			continue;
		}

		if (ret < 0) {
			ep_err(ep, "epoll error %d", ret);
			break;
		}
		if (ev.data.fd != ep->sockfd) {
			ep_err(ep, "epoll invalid fd %d\n", ev.data.fd);
			continue;
		}
		if (ep->recv_state == RECV_PDU) {
			ret = tcp_read_msg(ep);
		}
		if (!ret && ep->recv_state == HANDLE_PDU) {
			ret = tcp_handle_msg(ep);
			if (ret >= 0) {
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

		/*
		 * ->read_msg returns -ENODATA when the connection
		 * is closed; that shouldn't count as an error.
		 */
		if (ret == -ENODATA) {
			ep_info(ep, "connection closed");
			break;
		}
		if (ret < 0) {
			ep_err(ep, "error %d retry %d",
			       ret, ep->kato_countdown);
			break;
		}
	}
out_close:
	close(epollfd);

out_disconnect:
	handle_disconnect(ep, !stopped);

	ep_info(ep, "%s",
		stopped ? "stopped" : "disconnected");
	pthread_exit(NULL);

	return NULL;
}

int run_endpoint(struct endpoint *ep, int id)
{
	int ret;

	ret = tcp_create_endpoint(ep, id);
	if (ret) {
		fprintf(stderr, "ep %d: create failed error %d\n",
			id, ret);
		return ret;
	}

retry:
	ret = tcp_accept_connection(ep);
	if (ret) {
		if (ret == -EAGAIN)
			goto retry;

		ep_err(ep, "accept failed error %d", ret);
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
		fprintf(stderr, "no memory\n");
		close(id);
		return NULL;
	}

	memset(ep, 0, sizeof(struct endpoint));

	ep->iface = iface;
	ep->ctx = etcd_dup(iface->ctx);
	ep->kato_countdown = ep->ctx->ttl;
	ep->kato_interval = KATO_INTERVAL;
	ep->maxh2cdata = 0x10000;
	ep->qid = -1;
	ep->recv_state = RECV_PDU;

	ret = run_endpoint(ep, id);
	if (ret) {
		ep_err(ep, "run_endpoint failed error %d", ret);
		goto out;
	}

	pthread_mutex_lock(&iface->ep_mutex);
	list_add(&ep->node, &iface->ep_list);
	pthread_mutex_unlock(&iface->ep_mutex);
	return ep;
out:
	etcd_exit(ep->ctx);
	free(ep);
	close(id);
	return NULL;
}

void dequeue_endpoint(struct endpoint *ep)
{
	if (ep->pthread) {
		pthread_join(ep->pthread, NULL);
	}
	list_del(&ep->node);
	etcd_exit(ep->ctx);
	free(ep);
}
