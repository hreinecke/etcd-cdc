#ifndef _NVMET_TCP_H
#define _NVMET_TCP_H

int tcp_create_endpoint(struct endpoint *ep, int id);
void tcp_destroy_endpoint(struct endpoint *ep);
struct ep_qe *tcp_acquire_tag(struct endpoint *ep, union nvme_tcp_pdu *pdu,
			      u16 ccid, u64 pos, u64 len);
struct ep_qe *tcp_get_tag(struct endpoint *ep, u16 tag);
void tcp_release_tag(struct endpoint *ep, struct ep_qe *qe);
int tcp_init_listener(struct host_iface *iface);
void tcp_destroy_listener(struct host_iface *iface);
int tcp_accept_connection(struct endpoint *ep);
int tcp_wait_for_connection(struct host_iface *iface);
int tcp_rma_read(struct endpoint *ep, void *buf, u64 _len);
int tcp_handle_msg(struct endpoint *ep);

#endif /* _NVMET_TCP_H */
