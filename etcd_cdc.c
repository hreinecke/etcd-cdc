/*
 * etcd_cdc.c
 * decentralized NVMe discovery controller
 *
 * Copyright (c) 2021 Hannes Reinecke <hare@suse.de>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software Foundation,
 *  Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 */
#define _GNU_SOURCE

#include <stdio.h>
#include <signal.h>
#include <sys/signalfd.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <dirent.h>
#include <getopt.h>
#include <sys/types.h>
#include <fcntl.h>

#include <sys/inotify.h>

#include "etcd_cdc.h"

char *default_configfs = "/sys/kernel/config/nvmet";
char *default_host = "localhost";
char *default_proto = "http";
char *default_prefix = "nvmet";

#define INOTIFY_BUFFER_SIZE 8192

int inotify_fd;
static int signal_fd;

static void inotify_loop(struct etcd_cdc_ctx *ctx)
{
	fd_set rfd;
	struct timeval tmo;
	char event_buffer[INOTIFY_BUFFER_SIZE]
		__attribute__ ((aligned(__alignof__(struct inotify_event))));

	for (;;) {
		int rlen, ret;
		char *iev_buf;

		FD_ZERO(&rfd);
		FD_SET(signal_fd, &rfd);
		FD_SET(inotify_fd, &rfd);
		tmo.tv_sec = ctx->ttl / 5;
		tmo.tv_usec = 0;
		ret = select(inotify_fd + 1, &rfd, NULL, NULL, &tmo);
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			fprintf(stderr, "select returned %d", errno);
			break;
		}
		if (ret == 0) {
			/* Select timeout, refresh lease */
			ret = etcd_lease_keepalive(ctx);
			continue;
		}
		if (!FD_ISSET(inotify_fd, &rfd)) {
			struct signalfd_siginfo fdsi;

			if (!FD_ISSET(signal_fd, &rfd)) {
				fprintf(stderr,
					"select returned for invalid fd");
				continue;
			}
			rlen = read(signal_fd, &fdsi, sizeof(fdsi));
			if (rlen != sizeof(fdsi)) {
				fprintf(stderr,
					"Couldn't read siginfo\n");
				exit(1);
			}
			if (fdsi.ssi_signo == SIGINT ||
			    fdsi.ssi_signo == SIGTERM) {
				fprintf(stderr,
					"signal %d received, terminating\n",
					fdsi.ssi_signo);
				break;
			}
		}
		rlen = read(inotify_fd, event_buffer, INOTIFY_BUFFER_SIZE);
		if (rlen < 0) {
			fprintf(stderr, "error %d on reading inotify event",
				errno);
			continue;
		}
		for (iev_buf = event_buffer;
		     iev_buf < event_buffer + rlen; ) {
			int iev_len;

			iev_len = process_inotify_event(ctx, iev_buf,
							event_buffer + rlen - iev_buf);
			if (iev_len < 0) {
				fprintf(stderr, "Failed to process inotify\n");
				break;
			}
			iev_buf += iev_len;
		}
	}
}

int parse_opts(struct etcd_cdc_ctx *ctx, int argc, char *argv[])
{
	struct option getopt_arg[] = {
		{"configfs", required_argument, 0, 'c'},
		{"etcd_prefix", required_argument, 0, 'e'},
		{"port", required_argument, 0, 'p'},
		{"host", required_argument, 0, 'h'},
		{"ssl", no_argument, 0, 's'},
		{"ttl", required_argument, 0, 't'},
		{"verbose", no_argument, 0, 'v'},
	};
	char c;
	int getopt_ind;

	while ((c = getopt_long(argc, argv, "c:e:p:h:st:v",
				getopt_arg, &getopt_ind)) != -1) {
		switch (c) {
		case 'c':
			ctx->configfs = optarg;
			break;
		case 'e':
			ctx->prefix = optarg;
			break;
		case 'h':
			ctx->host = optarg;
			break;
		case 'p':
			ctx->port = atoi(optarg);
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
		}
	}
	return 0;
}

int main (int argc, char *argv[])
{
	struct etcd_cdc_ctx *ctx;
	sigset_t sigmask;
	int ret;

	ctx = malloc(sizeof(struct etcd_cdc_ctx));
	if (!ctx) {
		fprintf(stderr, "cannot allocate context\n");
		exit(1);
	}
	ctx->host = default_host;
	ctx->configfs = default_configfs;
	ctx->proto = default_proto;
	ctx->prefix = default_prefix;
	ctx->port = 2379;
	ctx->lease = -1;
	ctx->ttl = 30;

	parse_opts(ctx, argc, argv);

	ret = etcd_lease_grant(ctx);
	if (ret < 0)
		exit(1);
	sigemptyset(&sigmask);
	sigaddset(&sigmask, SIGINT);
	sigaddset(&sigmask, SIGTERM);

	if (sigprocmask(SIG_BLOCK, &sigmask, NULL) < 0) {
		fprintf(stderr, "Couldn't block signals, error %d\n", errno);
		exit(1);
	}
	signal_fd = signalfd(-1, &sigmask, 0);
	if (signal_fd < 0) {
		fprintf(stderr, "Couldn't setup signal fd, error %d\n", errno);
		exit(1);
	}
	inotify_fd = inotify_init();
	if (inotify_fd < 0) {
		fprintf(stderr, "Could not setup inotify, error %d\n", errno);
		exit(1);
	}

	watch_subsys_dir(ctx);
	watch_port_dir(ctx);

	inotify_loop(ctx);

	cleanup_watcher();

	close(inotify_fd);
	close(signal_fd);
	etcd_lease_revoke(ctx);
	free(ctx);
	return 0;
}
