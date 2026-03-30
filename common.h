/* SPDX-License-Identifier: DUAL GPL-2.0/BSD */
/*
 * common.h
 * Common definitions for NVMe-over-TCP userspace daemon
 *
 * Copyright (c) 2021 Hannes Reinecke <hare@suse.de>. All rights reserved.
 */
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

#include "utils.h"

extern bool tcp_debug;
extern bool cmd_debug;
extern bool ep_debug;
extern bool port_debug;
extern bool fuse_debug;
extern bool configfs_debug;

extern struct linked_list device_linked_list;
extern struct linked_list port_linked_list;

#define NVMET_CONFIGFS "/sys/kernel/config/nvmet"

#define NOFUSE_NGUID_PREFIX "0efd376f6e756665"

extern int stopped;

#define ep_info(e, f, x...)				\
	if (ep_debug) {					\
		printf("ep %d: " f "\n",		\
		       (e)->sockfd, ##x);		\
		fflush(stdout);				\
}

#define ep_err(e, f, x...)				\
	do {						\
		fprintf(stderr, "ep %d: " f "\n",	\
			(e)->sockfd, ##x);		\
		fflush(stderr);				\
	} while (0)


#define ctrl_info(e, f, x...)					\
	if (cmd_debug) {					\
		if ((e)->ctrl) {				\
			printf("ctrl %d qid %d: " f "\n",	\
			       (e)->ctrl->cntlid,		\
			       (e)->qid, ##x);			\
		} else {					\
			printf("ep %d: " f "\n",		\
			       (e)->sockfd, ##x);		\
		}						\
		fflush(stdout);					\
	}

#define ctrl_err(e, f, x...)					\
	do {							\
		if ((e)->ctrl) {				\
			fprintf(stderr,				\
				"ctrl %d qid %d: " f "\n",	\
				(e)->ctrl->cntlid,		\
				(e)->qid, ##x);			\
		} else {					\
			fprintf(stderr, "ep %d: " f "\n",	\
			       (e)->sockfd, ##x);		\
		}						\
		fflush(stderr);					\
	} while (0)

#define port_info(i, f, x...)			\
	if (port_debug) {			\
		printf("port %d: " f "\n",	\
		       (i)->portid, ##x);	\
		fflush(stdout);			\
	}

#define port_err(i, f, x...)				\
	do {						\
		fprintf(stderr, "port %d: " f "\n",	\
			(i)->portid, ##x);		\
		fflush(stderr);				\
	} while (0)

#endif
