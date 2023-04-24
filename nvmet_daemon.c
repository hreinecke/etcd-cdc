
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
int stopped;
int debug;
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

static int get_iface(struct etcd_cdc_ctx *ctx, const char *ifname)
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
		iface = new_host_iface(host, ifa->ifa_addr->sa_family, 8009);
		if (iface) {
			iface->ctx = ctx;
			list_add_tail(&iface->node, &iface_linked_list);
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
		id = tcp_wait_for_connection(iface);

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

static int add_host_port(int port)
{
	int iface_num = 0;
	LIST_HEAD(tmp_iface_list);
	struct host_iface *iface, *new;

	list_for_each_entry(iface, &iface_linked_list, node) {
		if (iface->port_num == port)
			continue;
		new = new_host_iface(iface->address, iface->adrfam, port);
		if (new) {
			list_add_tail(&new->node, &tmp_iface_list);
			iface_num++;
		}
	}

	list_splice(&tmp_iface_list, &iface_linked_list);
	return iface_num;
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
	int port_num[16];
	int port_max = 0, port, idx;
	int iface_num = 0;
	struct option getopt_arg[] = {
		{"help", no_argument, 0, '?'},
		{"discovery_nqn", required_argument, 0, 'd'},
		{"standalone", no_argument, 0, 'S'},
		{"interface", required_argument, 0, 'i'},
		{"prefix", required_argument, 0, 'e'},
		{"etcd_port", required_argument, 0, 'p'},
		{"etcd_host", required_argument, 0, 'h'},
		{"etcd_ssl", no_argument, 0, 's'},
		{"ttl", required_argument, 0, 't'},
		{"verbose", no_argument, 0, 'v'},
		{NULL, 0, 0, 0},
	};
	int getopt_ind;

	discovery_nqn = NULL;
	debug = 0;
	run_as_daemon = 1;

	while ((opt = getopt_long(argc, argv, "d:Si:e:p:h:st:v?",
				  getopt_arg, &getopt_ind)) != -1) {
		switch (opt) {
		case 'd':
			discovery_nqn = optarg;
			break;
		case 'S':
			run_as_daemon = 0;
			break;
		case 'e':
			ctx->prefix = optarg;
			break;
		case 'i':
			if (get_iface(ctx, optarg) < 0) {
				fprintf(stderr, "Invalid interface %s\n",
					optarg);
				return 1;
			}
			iface_num++;
			break;
		case 'p':
			errno = 0;
			if (port_max >= 16) {
				fprintf(stderr,
					"Too many port numbers specified\n");
				return 1;
			}
			port = strtoul(optarg, &eptr, 10);
			if (errno || port == 0 || port > LONG_MAX) {
				fprintf(stderr, "Invalid port number '%s'\n",
					optarg);
				return 1;
			}
			ctx->port = port;
			break;
		case 's':
			ctx->proto = "https";
			break;
		case 't':
			ctx->ttl = atoi(optarg);
			break;
		case 'v':
			ctx->debug++;
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
		if (get_iface(ctx, "lo") < 0) {
			fprintf(stderr, "Failed to initialize iface 'lo'\n");
			return 1;
		}
		iface_num++;
	}

	for (idx = 0; idx < port_max; idx++)
		add_host_port(port_num[idx]);

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

	ret = parse_args(ctx, argc, argv);
	if (ret) {
		etcd_exit(ctx);
		return ret;
	}

	signalled = stopped = 0;

	list_for_each_entry(iface, &iface_linked_list, node) {
		pthread_attr_t pthread_attr;

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
	etcd_exit(ctx);
	return ret;
}
