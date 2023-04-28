
#define _GNU_SOURCE
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <pthread.h>
#include <limits.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <json-c/json.h>
#include "nvmet_common.h"
#include "nvmet_endpoint.h"
#include "nvmet_tcp.h"

LIST_HEAD(iface_linked_list);

char *discovery_nqn;
int discovery_port = 8009;
int stopped;
int debug;
int tcp_debug;
static int signalled;
static int portid;

static void signal_handler(int sig_num)
{
	signalled = sig_num;
	stopped = 1;
}

static int daemonize(void)
{
	pid_t pid, sid;

	pid = fork();
	if (pid < 0) {
		fprintf(stderr, "fork failed, error %d\n", pid);
		return pid;
	}

	if (pid) /* if parent, exit to allow child to run as daemon */
		exit(0);

	umask(0022);

	sid = setsid();
	if (sid < 0) {
		fprintf(stderr, "setsid failed, error %d\n", sid);
		return sid;
	}

	if ((chdir("/")) < 0) {
		fprintf(stderr, "could not change dir to /\n");
		return -1;
	}

	return 0;
}

static struct host_iface *new_host_iface(const char *ifaddr,
					 int adrfam, int port)
{
	struct host_iface *iface;

	/* Check for duplicates */
	list_for_each_entry(iface, &iface_linked_list, node) {
		if (!strcmp(iface->address, ifaddr) &&
		    iface->port_num == port)
			return NULL;
	}
	iface = malloc(sizeof(*iface));
	if (!iface)
		return NULL;
	memset(iface, 0, sizeof(*iface));
	strcpy(iface->address, ifaddr);
	iface->adrfam = adrfam;
	if (iface->adrfam != AF_INET && iface->adrfam != AF_INET6) {
		fprintf(stderr, "invalid address family %d\n", adrfam);
		free(iface);
		return NULL;
	}
	iface->portid = portid++;
	iface->port_num = port;
	pthread_mutex_init(&iface->ep_mutex, NULL);
	INIT_LIST_HEAD(&iface->ep_list);
	printf("iface %d: listening on %s address %s port %d\n",
	       iface->portid,
	       iface->adrfam == AF_INET ? "ipv4" : "ipv6",
	       iface->address, iface->port_num);

	return iface;
}

static int register_host_iface(struct host_iface *iface)
{
	char key[1024], value[1024];

	if (iface->adrfam == AF_INET) {
		sprintf(key, "%s/%s/%s/%s:%d", iface->ctx->prefix,
			NVME_DISC_SUBSYS_NAME, iface->ctx->discovery_nqn,
			iface->address, iface->port_num);
	} else {
		sprintf(key, "%s/%s/%s/[%s]:%d", iface->ctx->prefix,
			NVME_DISC_SUBSYS_NAME, iface->ctx->discovery_nqn,
			iface->address, iface->port_num);
	}
	sprintf(value, "trtype=tcp,traddr=%s,trsvcid=%d,adrfam=%s",
		iface->address,iface->port_num,
		iface->adrfam == AF_INET ? "ipv4" : "ipv6");
	if (etcd_kv_put(iface->ctx, key, value, true) < 0) {
		fprintf(stderr, "cannot add key %s, error %d\n",
			key, errno);
		return -1;
	}
	printf("registered key %s: %s\n", key, value);
	nvmet_etcd_set_genctr(iface->ctx, 1);
	return 0;
}

static int get_iface(struct etcd_cdc_ctx *ctx, const char *ifname, int port)
{
	struct ifaddrs *ifaddrs, *ifa;

	if (getifaddrs(&ifaddrs) == -1) {
		perror("getifaddrs");
		return -1;
	}


	for (ifa = ifaddrs; ifa != NULL; ifa = ifa->ifa_next) {
		char host[NI_MAXHOST];
		struct host_iface *iface;
		int ret, addrlen;

		if (ifa->ifa_addr == NULL)
			continue;

		if (strcmp(ifa->ifa_name, ifname))
			continue;

		if (ifa->ifa_addr->sa_family == AF_INET)
			addrlen = sizeof(struct sockaddr_in);
		else if (ifa->ifa_addr->sa_family == AF_INET6)
			addrlen = sizeof(struct sockaddr_in6);
		else
			continue;

		ret = getnameinfo(ifa->ifa_addr, addrlen,
				  host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
		if (ret) {
			fprintf(stderr, "getnameinfo failed, error %d\n", ret);
			continue;
		}
		iface = new_host_iface(host, ifa->ifa_addr->sa_family, port);
		if (iface) {
			iface->ctx = ctx;
			list_add_tail(&iface->node, &iface_linked_list);
		}
        }
	freeifaddrs(ifaddrs);
	return 0;
}

static int get_address(struct etcd_cdc_ctx *ctx, const char *arg)
{
	struct ifaddrs *ifaddrs, *ifa;
	char *addr, *port_str, *eptr;
	int port = discovery_port;

	addr = strdup(arg);
	port_str = strrchr(addr, ':');
	if (port_str) {
		*port_str = '\0';
		port_str++;
		port = strtoul(port_str, &eptr, 10);
		if (port == 0 || port_str == eptr) {
			fprintf(stderr, "Invalid address %s\n", arg);
			return -1;
		}
	}

	if (getifaddrs(&ifaddrs) == -1) {
		perror("getifaddrs");
		return -1;
	}

	for (ifa = ifaddrs; ifa != NULL; ifa = ifa->ifa_next) {
		char host[NI_MAXHOST];
		struct host_iface *iface;
		int ret, addrlen;

		if (ifa->ifa_addr == NULL)
			continue;

		if (ifa->ifa_addr->sa_family == AF_INET)
			addrlen = sizeof(struct sockaddr_in);
		else if (ifa->ifa_addr->sa_family == AF_INET6)
			addrlen = sizeof(struct sockaddr_in6);
		else
			continue;

		ret = getnameinfo(ifa->ifa_addr, addrlen,
				  host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
		if (ret) {
			fprintf(stderr, "getnameinfo failed, error %d\n", ret);
			continue;
		}
		if (!strcmp(host, addr)) {
			iface = new_host_iface(host, ifa->ifa_addr->sa_family,
					       port);
			if (iface) {
				iface->ctx = ctx;
				list_add_tail(&iface->node, &iface_linked_list);
			}
			break;
		}
        }
	freeifaddrs(ifaddrs);
	return 0;
}

void *run_host_interface(void *arg)
{
	struct host_iface *iface = arg;
	struct endpoint *ep, *_ep;
	sigset_t set;
	int id;
	pthread_attr_t pthread_attr;
	int ret;

	sigemptyset(&set);
	sigaddset(&set, SIGPIPE);
	sigaddset(&set, SIGINT);
	sigaddset(&set, SIGTERM);
	pthread_sigmask(SIG_BLOCK, &set, NULL);

	ret = tcp_init_listener(iface);
	if (ret < 0) {
		fprintf(stderr,
			"iface %d: failed to start listener, error %d\n",
			iface->portid, ret);
		pthread_exit(NULL);
		return NULL;
	}

	while (!stopped) {
		id = tcp_wait_for_connection(iface, KATO_INTERVAL);

		if (stopped)
			break;

		if (id < 0) {
			if (id != -EAGAIN)
				fprintf(stderr,
					"iface %d: listener connection failed, error %d\n", iface->portid, id);
			continue;
		}
		ep = enqueue_endpoint(id, iface);
		if (!ep)
			continue;

		pthread_attr_init(&pthread_attr);

		ret = pthread_create(&ep->pthread, &pthread_attr,
				     endpoint_thread, ep);
		if (ret) {
			ep->pthread = 0;
			fprintf(stderr,
				"iface %d: failed to start endpoint thread, error %d\n",
				iface->portid, ret);
		}
		pthread_attr_destroy(&pthread_attr);
	}

	printf("iface %d: destroy listener\n", iface->portid);

	tcp_destroy_listener(iface);
	pthread_mutex_lock(&iface->ep_mutex);
	list_for_each_entry_safe(ep, _ep, &iface->ep_list, node)
		dequeue_endpoint(ep);
	pthread_mutex_unlock(&iface->ep_mutex);
	pthread_exit(NULL);
	return NULL;
}

static void show_help(char *app, struct option args[])
{
	struct option *opt = args;

	printf("Usage: %s <options>\n", app);

	for (opt = args; opt->name != NULL; opt++)
		printf("  -%c / --%s\n", opt->val, opt->name);
}

static int parse_args(struct etcd_cdc_ctx *ctx, int argc, char *argv[])
{
	int opt;
	int run_as_daemon;
	char *eptr;
	int port;
	struct option getopt_arg[] = {
		{"help", no_argument, 0, '?'},
		{"daemon", no_argument, 0, 'd'},
		{"discovery_nqn", required_argument, 0, 'n'},
		{"discovery_port", required_argument, 0, 'p'},
		{"address", required_argument, 0, 'a'},
		{"interface", required_argument, 0, 'i'},
		{"prefix", required_argument, 0, 'e'},
		{"etcd_port", required_argument, 0, 'P'},
		{"etcd_host", required_argument, 0, 'H'},
		{"etcd_ssl", no_argument, 0, 'S'},
		{"ttl", required_argument, 0, 't'},
		{"verbose", no_argument, 0, 'v'},
		{NULL, 0, 0, 0},
	};
	int getopt_ind;

	discovery_nqn = NULL;
	discovery_port = 8009;
	debug = 0;
	run_as_daemon = 0;

	while ((opt = getopt_long(argc, argv, "a:dn:p:i:e:P:H:St:v?",
				  getopt_arg, &getopt_ind)) != -1) {
		switch (opt) {
		case 'a':
			if (get_address(ctx, optarg) < 0) {
				fprintf(stderr, "Invalid address '%s'\n",
					optarg);
				return 1;
			}
			break;
		case 'd':
			run_as_daemon= 1;
			break;
		case 'n':
			ctx->discovery_nqn = strdup(optarg);
			break;
		case 'p':
			errno = 0;
			port = strtoul(optarg, &eptr, 10);
			if (errno || port == 0 || optarg == eptr) {
				fprintf(stderr, "Invalid port number '%s'\n",
					optarg);
				return 1;
			}
			discovery_port = port;
			break;
		case 'i':
			if (get_iface(ctx, optarg, discovery_port) < 0) {
				fprintf(stderr, "Invalid interface %s\n",
					optarg);
				return 1;
			}
			break;
		case 'e':
			ctx->prefix = optarg;
			break;
		case 'P':
			port = strtoul(optarg, &eptr, 10);
			if (errno || port == 0 || optarg == eptr) {
				fprintf(stderr, "Invalid port number '%s'\n",
					optarg);
				return 1;
			}
			ctx->port = port;
			break;
		case 'S':
			ctx->proto = "https";
			break;
		case 't':
			ctx->ttl = atoi(optarg);
			break;
		case 'v':
			ctx->debug++;
			if (ctx->debug > 1)
			    tcp_debug = 1;
			break;
		case '?':
		default:
help:
			show_help(argv[0], getopt_arg);
			return 1;
		}
	}

	if (optind < argc) {
		printf("Extra arguments");
		goto help;
	}

	if (list_empty(&iface_linked_list)) {
		if (get_iface(ctx, "lo", discovery_port) < 0) {
			fprintf(stderr, "Failed to initialize iface 'lo'\n");
			return 1;
		}
	}

	if (list_empty(&iface_linked_list)) {
		fprintf(stderr, "invalid host interface configuration\n");
		return 1;
	}

	if (run_as_daemon) {
		if (daemonize())
			return 1;
	}

	return 0;
}

void terminate_interfaces(struct host_iface *iface, int signo)
{
	struct host_iface *_iface;

	stopped = true;
	list_for_each_entry(_iface, &iface_linked_list, node) {
		if (_iface == iface)
			continue;
		fprintf(stderr, "iface %d: terminating\n",
			_iface->portid);
		pthread_kill(iface->pthread, signo);
	}
}

void free_interfaces(void)
{
	struct host_iface *iface, *_iface;

	list_for_each_entry_safe(iface, _iface, &iface_linked_list, node) {
		if (iface->pthread)
			pthread_join(iface->pthread, NULL);
		pthread_mutex_destroy(&iface->ep_mutex);
		list_del(&iface->node);
		if (iface->tls_key)
			free(iface->tls_key);
		free(iface);
	}
}

int main(int argc, char *argv[])
{
	int ret = 1;
	struct host_iface *iface;
	struct etcd_cdc_ctx *ctx;

	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	ctx = etcd_init();
	if (!ctx)
		return 1;

	ctx->ttl = RETRY_COUNT;
	signalled = stopped = 0;

	ret = parse_args(ctx, argc, argv);
	if (ret) {
		etcd_exit(ctx);
		return ret;
	}

	ret = etcd_lease_grant(ctx);
	if (ret < 0) {
		etcd_exit(ctx);
		return ret;
	}

	nvmet_etcd_discovery_nqn(ctx);

	list_for_each_entry(iface, &iface_linked_list, node) {
		pthread_attr_t pthread_attr;

		ret = register_host_iface(iface);
		if (ret)
			continue;
		pthread_attr_init(&pthread_attr);

		ret = pthread_create(&iface->pthread, &pthread_attr,
				     run_host_interface, iface);
		if (ret) {
			iface->pthread = 0;
			fprintf(stderr,
				"failed to start iface thread, error %d", ret);
		}
		pthread_attr_destroy(&pthread_attr);
	}

	free_interfaces();
	etcd_lease_revoke(ctx);
	etcd_exit(ctx);
	return ret;
}
