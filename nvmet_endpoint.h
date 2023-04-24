#ifndef _NVMET_ENDPOINT_H
#define _NVMET_ENDPOINT_H

void *endpoint_thread(void *arg);
struct endpoint *enqueue_endpoint(int id, struct host_iface *iface);
void dequeue_endpoint(struct endpoint *ep);

#endif /* _NVMET_ENDPOINT_H */

