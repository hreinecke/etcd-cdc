#define _GNU_SOURCE
#include <stdbool.h>
#include <stddef.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <netinet/in.h>

#include "types.h"
#include "nvme.h"
#include "nvme_tcp.h"
#include "nvmet_common.h"
#include "nvmet_tcp.h"

#define NVME_OPCODE_MASK 0x3
#define NVME_OPCODE_H2C  0x1
#define NVME_OPCODE_C2H  0x2

#define BACKLOG			16
#define RESOLVE_TIMEOUT		5000
#define EVENT_TIMEOUT		200

#define TCP_SYNCNT		7
#define TCP_NODELAY		1

#define tcp_info(e, f, x...)					\
	if (tcp_debug) {					\
		printf("ctrl %d qid %d: " f "\n",		\
		       (e)->ctrl ? (e)->ctrl->cntlid : -1,	\
		       (e)->qid, ##x);				\
		fflush(stdout);					\
	}

#define tcp_err(e, f, x...)					\
	do {							\
		fprintf(stderr, "ctrl %d qid %d: " f "\n",	\
		       (e)->ctrl ? (e)->ctrl->cntlid : -1,	\
		       (e)->qid, ##x);				\
		fflush(stderr);					\
	} while (0)

static int tcp_ep_read(struct endpoint *ep, void *buf, size_t buf_len)
{
	return read(ep->sockfd, buf, buf_len);
}

static int tcp_ep_write(struct endpoint *ep, void *buf, size_t buf_len)
{
	return write(ep->sockfd, buf, buf_len);
}

int tcp_create_endpoint(struct endpoint *ep, int id)
{
	int flags, i;

	ep->sockfd = id;

	flags = fcntl(ep->sockfd, F_GETFL);
	fcntl(ep->sockfd, F_SETFL, flags | O_NONBLOCK);

	ep->send_pdu = malloc(sizeof(union nvme_tcp_pdu));
	if (!ep->send_pdu) {
		tcp_err(ep, "no memory");
		return -ENOMEM;
	}

	ep->recv_pdu = malloc(sizeof(union nvme_tcp_pdu));
	if (!ep->recv_pdu) {
		free(ep->send_pdu);
		ep->send_pdu = NULL;
		tcp_err(ep, "no memory");
		return -ENOMEM;
	}

	ep->qes = calloc(NVMF_SQ_DEPTH, sizeof(struct ep_qe));
	if (!ep->qes) {
		free(ep->recv_pdu);
		ep->recv_pdu = NULL;
		free(ep->send_pdu);
		ep->send_pdu = NULL;
		return -ENOMEM;
	}
	ep->qsize = NVMF_SQ_DEPTH;
	for (i = 0; i < ep->qsize; i++) {
		ep->qes[i].tag = i;
		ep->qes[i].ep = ep;
	}
	return 0;
}

void tcp_destroy_endpoint(struct endpoint *ep)
{
	if (ep->qes) {
		free(ep->qes);
		ep->qes = NULL;
	}
	if (ep->recv_pdu) {
		free(ep->recv_pdu);
		ep->recv_pdu = NULL;
	}
	if (ep->send_pdu) {
		free(ep->send_pdu);
		ep->send_pdu = NULL;
	}
	if (ep->sockfd >= 0) {
		close(ep->sockfd);
		ep->sockfd = -1;
	}
}

struct ep_qe *tcp_acquire_tag(struct endpoint *ep, union nvme_tcp_pdu *pdu,
			      u16 ccid, u64 pos, u64 len)
{
	int i;

	for (i = 0; i < ep->qsize; i++) {
		struct ep_qe *qe = &ep->qes[i];

		if (!qe->busy) {
			qe->busy = true;
			qe->ccid = ccid;
			if (len) {
				qe->data = malloc(len);
				if (!qe->data) {
					tcp_err(ep,
						"Error allocating iovec base");
					return NULL;
				}
				qe->data_pos = pos;
				qe->data_len = len;
				qe->iovec.iov_base = NULL;
				qe->iovec.iov_len = 0;
				qe->iovec_offset = 0;
				qe->data_remaining = 0;
			}
			memcpy(&qe->pdu, pdu,
			       sizeof(union nvme_tcp_pdu));
			memset(&qe->resp, 0, sizeof(qe->resp));
			qe->resp.command_id = 0xffff;
			tcp_info(ep, "acquire tag %#x", qe->tag);
			return qe;
		}
	}
	return NULL;
}

struct ep_qe *tcp_get_tag(struct endpoint *ep, u16 tag)
{
	if (tag >= ep->qsize || !ep->qes[tag].busy)
		return NULL;
	return &ep->qes[tag];
}

void tcp_release_tag(struct endpoint *ep, struct ep_qe *qe)
{
	if (!qe)
		return;
	if (&ep->qes[qe->tag] != qe)
		return;

	qe->busy = false;
	if (qe->data) {
		free(qe->data);
		qe->data = NULL;
		qe->data_len = 0;
	}
	qe->iovec.iov_base = NULL;
	qe->iovec.iov_len = 0;
	tcp_info(ep, "release tag %#x", qe->tag);
}

int tcp_init_listener(struct host_iface *iface)
{
	int listenfd;
	int ret;

	listenfd = socket(iface->adrfam, SOCK_STREAM|SOCK_NONBLOCK, 0);
	if (listenfd < 0) {
		fprintf(stderr, "iface %d: socket error %d\n",
			iface->portid, errno);
		return -errno;
	}

	if (iface->adrfam == AF_INET) {
		struct sockaddr_in addr;
		memset(&addr, 0, sizeof(addr));
		addr.sin_family = iface->adrfam;
		addr.sin_port = htons(iface->port_num);
		inet_pton(AF_INET, iface->address, &addr.sin_addr);

		ret = bind(listenfd, (struct sockaddr *) &addr, sizeof(addr));
		if (ret < 0) {
			fprintf(stderr, "iface %d: socket bind error %d\n",
				  iface->portid, errno);
			ret = -errno;
			goto err;
		}
	} else {
		struct sockaddr_in6 addr6;
		memset(&addr6, 0, sizeof(addr6));
		addr6.sin6_family = iface->adrfam;
		addr6.sin6_port = htons(iface->port_num);
		inet_pton(AF_INET6, iface->address, &addr6.sin6_addr);

		ret = bind(listenfd, (struct sockaddr *) &addr6, sizeof(addr6));
		if (ret < 0) {
			fprintf(stderr, "iface %d: socket bind error %d\n",
				  iface->portid, errno);
			ret = -errno;
			goto err;
		}
	}
	ret = listen(listenfd, BACKLOG);
	if (ret < 0) {
		fprintf(stderr, "iface %d: socket listen error %d\n",
			iface->portid, errno);
		ret = -errno;
		goto err;
	}
	iface->listenfd = listenfd;
	return 0;
err:
	close(listenfd);
	return ret;
}

void tcp_destroy_listener(struct host_iface *iface)
{
	close(iface->listenfd);
	iface->listenfd = -1;
}

int tcp_accept_connection(struct endpoint *ep)
{
	struct nvme_tcp_icreq_pdu *icreq = NULL;
	struct nvme_tcp_icresp_pdu *icrep;
	int ret, len, hdr_len;

	if (!ep)
		return -EINVAL;

	icreq = malloc(sizeof(*icreq));
	if (!icreq)
		return -ENOMEM;

	memset(icreq, 0, sizeof(*icreq));

	hdr_len = sizeof(struct nvme_tcp_hdr);
	ret = tcp_ep_read(ep, icreq, hdr_len);
	if (ret < 0) {
		if (errno != EAGAIN)
			tcp_err(ep, "icreq header read, error %d", errno);
		return -errno;
	}
	if (ret != hdr_len) {
		tcp_err(ep, "icreq short header read, %d bytes missing",
			hdr_len - ret);
		ret = (ret < 0) ? -EAGAIN : -ENODATA;
		goto out_free;
	}

	if (icreq->hdr.type == 0) {
		len = icreq->hdr.hlen - hdr_len;
		ret = tcp_ep_read(ep, (u8 *)icreq + hdr_len, len);
		if (ret < 0) {
			tcp_err(ep, "icreq read error %d", errno);
			ret = -errno;
			goto out_free;
		}
		if (ret != len) {
			tcp_err(ep, "icreq short read, %d bytes missing",
			       len - ret);
			ret = -ENODATA;
			goto out_free;
		}
		if (icreq->hpda != 0) {
			ret = -EPROTO;
			goto out_free;
		}
		ep->maxr2t = le32toh(icreq->maxr2t) + 1;
	}

	tcp_info(ep, "read %d icreq bytes (type %d, maxr2t %u)",
		icreq->hdr.hlen, icreq->hdr.type, icreq->maxr2t);

	icrep = malloc(sizeof(*icrep));
	if (!icrep) {
		ret = -ENOMEM;
		goto out_free;
	}

	memset(icrep, 0, sizeof(*icrep));
	icrep->hdr.type = nvme_tcp_icresp;
	icrep->hdr.hlen = sizeof(*icrep);
	icrep->hdr.pdo = 0;
	icrep->hdr.plen = htole32(sizeof(*icrep));
	icrep->pfv = htole16(NVME_TCP_PFV_1_0);
	icrep->maxdata = 0xf000;
	icrep->cpda = 0;
	icrep->digest = 0;

	len = tcp_ep_write(ep, icrep, sizeof(*icrep));
	if (len < 0) {
		tcp_err(ep, "icresp write error %d", errno);
		return -errno;
	}
	if (len != sizeof(*icrep)) {
		tcp_err(ep, "icrep short write, %ld bytes missing",
			sizeof(*icrep) - len);
		ret = -ENODATA;
	} else {
		tcp_info(ep, "wrote %d icresp bytes", len);
		ret = 0;
	}

	free(icrep);
out_free:
	free(icreq);
	return ret;
}

int tcp_wait_for_connection(struct host_iface *iface, int timeout_ms)
{
	int epollfd;
	struct epoll_event ev[2];
	int sockfd, sigfd;
	int ret = -ESHUTDOWN, n;
	sigset_t sigmask;

	epollfd = epoll_create(2);
	if (epollfd < 0) {
		fprintf(stderr, "iface %d: epoll create error %d\n",
			iface->portid, errno);
		return -errno;
	}

	ev[0].events = EPOLLIN;
	ev[0].data.fd = iface->listenfd;
	if (epoll_ctl(epollfd, EPOLL_CTL_ADD, iface->listenfd, &ev[0]) == -1) {
		fprintf(stderr, "iface %d: failed to add listen fd, error %d\n",
			iface->portid, errno);
		close(epollfd);
		return -errno;
	}
	sigemptyset(&sigmask);
	sigaddset(&sigmask, SIGINT);
	sigaddset(&sigmask, SIGTERM);
	sigfd = signalfd(-1, &sigmask, 0);
	if (sigfd < 0) {
		fprintf(stderr, "iface %d: signalfd error %d\n",
			iface->portid, errno);
		close(epollfd);
		return -errno;
	}
	ev[1].events = EPOLLIN;
	ev[1].data.fd = sigfd;
	if (epoll_ctl(epollfd, EPOLL_CTL_ADD, sigfd, &ev[1]) == -1) {
		fprintf(stderr, "iface %d: failed to add signalfd, error %d\n",
			iface->portid, errno);
		close(sigfd);
		close(epollfd);
		return -errno;
	}

	while (!stopped) {
		ret = epoll_pwait(epollfd, ev, 2, timeout_ms, &sigmask);
		if (ret < 0) {
			fprintf(stderr, "iface %d: epoll_wait error %d\n",
				iface->portid, errno);
			ret = -errno;
			break;
		}
		if (ret > 0)
			break;

		/* epoll timeout, refresh lease */
		ret = etcd_lease_keepalive(iface->ctx);
		if (ret < 0) {
			fprintf(stderr,
				"iface %d: lease keepalive error %d\n",
				iface->portid, ret);
			break;
		}
	}
	for (n = 0; n < ret; n++) {
		if (ev[n].data.fd == sigfd) {
			struct signalfd_siginfo fdsi;
			size_t rlen;

			rlen = read(sigfd, &fdsi, sizeof(fdsi));
			if (rlen != sizeof(fdsi)) {
				fprintf(stderr,
					"iface %d: signalfd error\n",
					iface->portid);
				ret = -ENOMSG;
			}
			fprintf(stderr,
				"iface %d: signal %d received, terminating\n",
				iface->portid, fdsi.ssi_signo);
			terminate_interfaces(iface, fdsi.ssi_signo);
			ret = -EINTR;
			break;
		}
	}
	close(sigfd);

	if (ret < 0)
		goto out_close;

	if (ret > 0) {
		sockfd = accept(iface->listenfd, (struct sockaddr *) NULL,
				NULL);
		if (sockfd < 0) {
			if (errno != EAGAIN)
				fprintf(stderr,
					"iface %d: failed to accept error %d\n",
					iface->portid, errno);
			ret = -EAGAIN;
		} else
			ret = sockfd;
	}
out_close:
	close(epollfd);
	return ret;
}

int tcp_recv_data(struct endpoint *ep, void *buf, u64 _len)
{
	int len = 0, offset = 0;
#if 0
	struct pollfd fds;

	fds.fd = ep->sockfd;
	fds.events = POLLIN | POLLERR;
#endif
	while (offset < _len) {
#if 0
		int ret;
		struct pollfd fds;

		ret = poll(&fds, 1, ep->kato_interval);
		if (ret <= 0) {
			if (ret < 0) {
				tcp_err(ep, "poll returned %d", errno);
				return -errno;
			}
			if (--ep->kato_countdown > 0)
				continue;
			tcp_err(ep, "poll timeout");
			return -ETIMEDOUT;
		}
#endif
		tcp_info(ep, "read %llu bytes",
			_len - offset);
		len = tcp_ep_read(ep, (u8 *)buf + offset, _len - offset);
		if (len < 0) {
			tcp_err(ep, "read returned %d", errno);
			return -errno;
		}
		offset += len;
	}
	return 0;
}

int tcp_send_c2h_data(struct endpoint *ep, struct ep_qe *qe)
{
	int len, send_pdu_len = 0;
	bool last = qe->data_remaining == qe->iovec.iov_len;
	struct nvme_tcp_data_pdu *pdu = &ep->send_pdu->data;

	tcp_info(ep, "c2h data cid %x offset %llu len %lu/%llu",
		  qe->ccid, qe->data_pos, qe->iovec.iov_len,
		  qe->data_remaining);

	if (!qe->data_remaining) {
		tcp_err(ep, "Nothing to send, %lu bytes left",
			 qe->iovec.iov_len);
		return 0;
	}
	memset(pdu, 0, sizeof(*pdu));
	pdu->hdr.type = nvme_tcp_c2h_data;
	pdu->hdr.flags = last ? (NVME_TCP_F_DATA_LAST | NVME_TCP_F_DATA_SUCCESS) : 0;
	pdu->hdr.pdo = 0;
	pdu->hdr.hlen = sizeof(struct nvme_tcp_data_pdu);
	pdu->hdr.plen = htole32(sizeof(struct nvme_tcp_data_pdu) +
				qe->iovec.iov_len);
	pdu->data_offset = htole32(qe->data_pos);
	pdu->data_length = htole32(qe->iovec.iov_len);
	pdu->command_id = qe->ccid;
	tcp_info(ep, "c2h hdr init %u/%u bytes",
		  pdu->hdr.hlen, pdu->hdr.plen);

	while (send_pdu_len < pdu->hdr.hlen) {
		u8 *data = (u8 *)pdu + send_pdu_len;
		u64 data_len = pdu->hdr.hlen - send_pdu_len;

		len = tcp_ep_write(ep, data, data_len);
		if (len < 0) {
			tcp_err(ep, "c2h hdr write returned %d", errno);
			return -errno;
		}
		if (len == 0) {
			tcp_err(ep, "c2h hdr write connection closed");
			return -ENODATA;
		}
		send_pdu_len += len;
		tcp_info(ep, "c2h hdr wrote %d bytes", len);
	}
	while (qe->iovec.iov_len) {
		u8 *data = qe->iovec.iov_base;

		len = tcp_ep_write(ep, data, qe->iovec.iov_len);
		if (len < 0) {
			tcp_err(ep, "c2h data write returned %d", errno);
			return -errno;
		}
		if (len == 0) {
			tcp_err(ep, "c2h data write connection closed");
			return -ENODATA;
		}
		qe->data_remaining -= len;
		data += len;
		qe->iovec.iov_base = data;
		qe->iovec.iov_len -= len;
		qe->iovec_offset += len;
		tcp_info(ep, "c2h data wrote %d bytes", len);
	}

	return 0;
}

int tcp_send_r2t(struct endpoint *ep, u16 tag)
{
	struct nvme_tcp_r2t_pdu *pdu = &ep->send_pdu->r2t;
	struct ep_qe *qe;
	int len;

	qe = tcp_get_tag(ep, tag);
	if (!qe) {
		tcp_err(ep, "invalid ttag %#x", tag);
		return -EINVAL;
	}

	tcp_info(ep, "r2t cid %#x ttag %#x offset %llu len %lu",
		  qe->ccid, qe->tag, qe->iovec_offset,
		  qe->iovec.iov_len);

	memset(pdu, 0, sizeof(*pdu));
	pdu->hdr.type = nvme_tcp_r2t;
	pdu->hdr.flags = 0;
	pdu->hdr.pdo = 0;
	pdu->hdr.hlen = sizeof(struct nvme_tcp_r2t_pdu);
	pdu->hdr.plen = htole32(sizeof(struct nvme_tcp_r2t_pdu));
	pdu->ttag = qe->tag;
	pdu->command_id = qe->ccid;
	pdu->r2t_offset = htole32(qe->iovec_offset);
	pdu->r2t_length = htole32(qe->iovec.iov_len);

	memcpy(&qe->pdu, pdu, sizeof(*pdu));

	len = tcp_ep_write(ep, pdu, sizeof(*pdu));
	if (len < 0) {
		tcp_err(ep, "r2t write returned %d", errno);
		return -errno;
	}
	if (len < sizeof(*pdu)) {
		tcp_err(ep, "short r2t write, %d bytes missing",
			 (int)sizeof(*pdu) - len);
		return -EAGAIN;
	}
	return 0;
}

int tcp_send_c2h_term(struct endpoint *ep, u16 fes, u8 pdu_offset,
			     u8 parm_offset, bool hdr_digest,
			     union nvme_tcp_pdu *pdu, int pdu_len)
{
	struct nvme_tcp_term_pdu *term_pdu = &ep->send_pdu->term;
	int len, plen;

	tcp_info(ep, "c2h term fes %u offset pdu %u parm %u",
		  fes, pdu_offset, parm_offset);

	if (!pdu)
		pdu_len = 0;
	if (pdu_len > 152 - sizeof(struct nvme_tcp_term_pdu))
		pdu_len = 152 - sizeof(struct nvme_tcp_term_pdu);
	plen = sizeof(struct nvme_tcp_term_pdu) + pdu_len;
	term_pdu->hdr.type = nvme_tcp_c2h_term;
	term_pdu->hdr.flags = 0;
	term_pdu->hdr.pdo = 0;
	term_pdu->hdr.hlen = sizeof(struct nvme_tcp_term_pdu);
	term_pdu->hdr.plen = htole32(plen);
	term_pdu->fes = htole16(fes);
	term_pdu->fei = htole32(parm_offset << 6 | pdu_offset << 1);

	len = tcp_ep_write(ep, term_pdu, sizeof(*term_pdu));
	if (len < 0) {
		tcp_err(ep, "c2h_term write returned %d", errno);
		return -errno;
	}
	if (len != sizeof(*term_pdu)) {
		tcp_err(ep, "c2h_term short write; %d bytes missing",
			 plen - len);
		return -EAGAIN;
	}
	if (pdu) {
		len = tcp_ep_write(ep, pdu, pdu_len);
		if (len < 0) {
			tcp_err(ep, "c2h term pdu write returned %d", errno);
			return -errno;
		}
		if (len != pdu_len) {
			tcp_err(ep, "c2h term short write; %d bytes missing",
				 pdu_len - len);
			return -EAGAIN;
		}
	}

	ep->recv_state = RECV_PDU;
	ep->recv_pdu_len = 0;

	/* Return -EPROTO to signal the connection should be dropped */
	return -EPROTO;
}

int tcp_send_rsp(struct endpoint *ep, struct nvme_completion *comp)
{
	struct nvme_tcp_rsp_pdu *pdu = &ep->send_pdu->rsp;
	int len;

	tcp_info(ep, "rsp tag %#x status %04x",
		  comp->command_id, comp->status);

	pdu->hdr.type = nvme_tcp_rsp;
	pdu->hdr.flags = 0;
	pdu->hdr.pdo = 0;
	pdu->hdr.hlen = sizeof(struct nvme_tcp_rsp_pdu);
	pdu->hdr.plen = sizeof(struct nvme_tcp_rsp_pdu);

	memcpy(&(pdu->cqe), comp, sizeof(struct nvme_completion));

	tcp_info(ep, "write %u pdu bytes", pdu->hdr.plen);
	len = tcp_ep_write(ep, pdu, pdu->hdr.plen);
	if (len != sizeof(*pdu)) {
		tcp_err(ep, "tcp_ep_write returned %d", errno);
		return -errno;
	}

	return 0;
}

int tcp_handle_h2c_data(struct endpoint *ep, union nvme_tcp_pdu *pdu)
{
	u16 ttag = le16toh(pdu->data.ttag);
	u32 data_offset = le32toh(pdu->data.data_offset);
	u32 data_len = le32toh(pdu->data.data_length);
	u8 *data;
	struct ep_qe *qe;
	int ret;

	tcp_info(ep, "h2c data tag %#x pos %u len %u",
		  ttag, data_offset, data_len);
	qe = tcp_get_tag(ep, ttag);
	if (!qe) {
		tcp_err(ep, "h2c invalid ttag %#x", ttag);
		return tcp_send_c2h_term(ep, NVME_TCP_FES_INVALID_PDU_HDR,
				offsetof(struct nvme_tcp_data_pdu, ttag),
				0, false, pdu, sizeof(struct nvme_tcp_data_pdu));
	}
	if (data_offset != qe->iovec_offset) {
		tcp_err(ep, "h2c offset mismatch, is %u exp %llu",
			 data_offset, qe->iovec_offset);
		return tcp_send_c2h_term(ep, NVME_TCP_FES_PDU_SEQ_ERR,
				offsetof(struct nvme_tcp_data_pdu, data_offset),
				0, false, pdu, sizeof(struct nvme_tcp_data_pdu));
	}
	if (data_len > qe->iovec.iov_len) {
		tcp_err(ep, "h2c len overflow, is %u exp %llu",
			 data_len, qe->data_remaining);
		return tcp_send_c2h_term(ep, NVME_TCP_FES_PDU_SEQ_ERR,
				offsetof(struct nvme_tcp_data_pdu, data_offset),
				0, false, pdu, sizeof(struct nvme_tcp_data_pdu));
	}

	ret = tcp_recv_data(ep, qe->iovec.iov_base, qe->iovec.iov_len);
	if (ret < 0) {
		tcp_err(ep, "h2c data read failed, error %d", errno);
		ret = NVME_SC_SGL_INVALID_DATA;
		goto out_rsp;
	}
	qe->data_remaining -= ret;
	qe->iovec_offset += ret;
	data = qe->iovec.iov_base;
	data += ret;
	qe->iovec.iov_base = data;
	qe->iovec.iov_len -= ret;
	if (!qe->data_remaining) {
		ret = 0;
		goto out_rsp;
	}

	return tcp_send_r2t(ep, qe->tag);
out_rsp:
	memset(&qe->resp, 0, sizeof(qe->resp));
	set_response(&qe->resp, qe->ccid, ret, true);
	return tcp_send_rsp(ep, &qe->resp);
}

int tcp_read_msg(struct endpoint *ep)
{
	u8 *msg = (u8 *)ep->recv_pdu + ep->recv_pdu_len;
	int len, msg_len;

	if (ep->recv_pdu_len < sizeof(struct nvme_tcp_hdr)) {
		msg_len = sizeof(struct nvme_tcp_hdr) - ep->recv_pdu_len;
		tcp_info(ep, "read %u msg bytes", msg_len);
		len = tcp_ep_read(ep, msg, msg_len);
		if (len < 0) {
			tcp_err(ep, "failed to read msg hdr, error %d",
				errno);
			return -errno;
		}
		/* No data received, disconnected */
		if (!len)
			return -ENODATA;

		ep->recv_pdu_len += len;
		msg_len -= len;
		if (msg_len) {
			tcp_err(ep, "short msg hdr read, %lu bytes missing",
				sizeof(struct nvme_tcp_hdr) - ep->recv_pdu_len);
			return -EAGAIN;
		}
	}
	if (!ep->recv_pdu->common.hlen) {
		tcp_err(ep, "corrupt hdr, hlen %d size %ld",
			ep->recv_pdu->common.hlen,
			sizeof(struct nvme_tcp_hdr));
		return tcp_send_c2h_term(ep, NVME_TCP_FES_INVALID_PDU_HDR,
					offsetof(struct nvme_tcp_hdr, hlen),
					0, false, NULL, 0);
	}
	msg_len = ep->recv_pdu->common.hlen - ep->recv_pdu_len;
	if (msg_len) {
		msg = (u8 *)ep->recv_pdu + ep->recv_pdu_len;

		tcp_info(ep, "read %u pdu bytes", msg_len);
		len = tcp_ep_read(ep, msg, msg_len);
		if (len == 0)
			return -EAGAIN;
		if (len < 0) {
			tcp_err(ep, "failed to read msg payload error %d",
				errno);
			return -errno;
		}
		ep->recv_pdu_len += len;
		msg_len -= len;
		if (msg_len > 0) {
			tcp_err(ep, "short msg payload read, %u bytes missing",
			       msg_len);
			return -EAGAIN;
		}
		ep->recv_state = HANDLE_PDU;
	}
	return 0;
}

int tcp_handle_msg(struct endpoint *ep)
{
	union nvme_tcp_pdu *pdu = ep->recv_pdu;
	struct nvme_tcp_hdr *hdr = &pdu->common;

	if (hdr->type == nvme_tcp_h2c_data)
		return tcp_handle_h2c_data(ep, pdu);

	if (hdr->type == nvme_tcp_h2c_term) {
		ep->recv_state = RECV_PDU;
		ep->recv_pdu_len = 0;
		tcp_info(ep, "h2c term, disconnecting");
		return -ENOTCONN;
	}

	if (hdr->type != nvme_tcp_cmd) {
		tcp_err(ep, "unknown PDU type %x", hdr->type);
		return tcp_send_c2h_term(ep, NVME_TCP_FES_PDU_SEQ_ERR,
					 offsetof(struct nvme_tcp_hdr, type),
					 0, false, pdu, hdr->hlen);
	}

	return handle_request(ep, &pdu->cmd.cmd);
}

int tcp_send_data(struct endpoint *ep, struct ep_qe *qe, u64 data_len)
{
	tcp_info(ep, "write cid %x offset %llu len %llu",
		  qe->ccid, qe->data_pos, data_len);

	qe->data_remaining = data_len;
	qe->iovec.iov_base = qe->data;
	qe->iovec.iov_len = (ep->mdts && data_len > ep->mdts) ?
		ep->mdts : data_len;
	qe->iovec_offset = 0;
	while (qe->data_remaining) {
		int ret = tcp_send_c2h_data(ep, qe);
		if (ret < 0) {
			tcp_release_tag(ep, qe);
			return ret;
		}
		data_len = qe->data_remaining;
		qe->iovec.iov_len = (ep->mdts && data_len > ep->mdts) ?
			ep->mdts : data_len;
	}
	tcp_release_tag(ep, qe);
	return 0;
}
