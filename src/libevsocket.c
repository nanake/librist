/* librist. Copyright © 2019 SipRadius LLC. All right reserved.
 * Author: Daniele Lacamera <root@danielinux.net>
 * Author: Sergio Ammirata, Ph.D. <sergio@ammirata.net>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "common/attributes.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#ifndef _WIN32
#include "log-private.h"
#endif

#ifdef _WIN32

#if !defined(UNDER_CE)
# define _NO_OLDNAMES 1
# include <io.h>
#endif

#include <winsock2.h>
#include "log-private.h"

/* Type used for the number of file descriptors. */
typedef unsigned long int nfds_t;

#if !defined(_WIN32_WINNT) || (_WIN32_WINNT < 0x0600)
/* Data structure describing a polling request. */
struct pollfd {
	int fd; /* file descriptor */
	short events; /* requested events */
	short revents; /* returned events */
};

/* Event types that can be polled */
#define POLLIN 0x001 /* There is data to read. */
#define POLLPRI 0x002 /* There is urgent data to read. */
#define POLLOUT 0x004 /* Writing now will not block. */

# define POLLRDNORM 0x040 /* Normal data may be read. */
# define POLLRDBAND 0x080 /* Priority data may be read. */
# define POLLWRNORM 0x100 /* Writing now will not block. */
# define POLLWRBAND 0x200 /* Priority data may be written. */

/* Event types always implicitly polled. */
#define POLLERR 0x008 /* Error condition. */
#define POLLHUP 0x010 /* Hung up. */
#define POLLNVAL 0x020 /* Invalid polling request. */

#endif

#include "contrib/poll_win.c"

#else
# include <poll.h>
#endif

#include "stdio-shim.h"
#include "libevsocket.h"
#include "socket-shim.h"
#include "pthread-shim.h"
#include "librist/udpsocket.h"

struct evsocket_event {
	int fd;
	short events;
	void (*callback)(struct evsocket_ctx *ctx, int fd, short revents, void *arg);
	void (*err_callback)(struct evsocket_ctx *ctx, int fd, short revents, void *arg);
	void *arg;
	struct evsocket_event *next;
};

struct evsocket_ctx {
	int changed;
	int n_events;
	int last_served;
	struct pollfd *pfd;
	struct evsocket_event *events;
	struct evsocket_event *_array;
	int giveup;
	struct evsocket_ctx *next;
};
#if !defined(_WIN32) || defined(HAVE_PTHREADS)
static pthread_mutex_t ctx_list_mutex = PTHREAD_MUTEX_INITIALIZER;
#else
static pthread_mutex_t ctx_list_mutex;
static INIT_ONCE once_var;
#endif

static struct evsocket_ctx *CTX_LIST = NULL;

static void ctx_add(struct evsocket_ctx *c)
{
#if defined(_WIN32) && !defined(HAVE_PTHREADS)
  	init_mutex_once(&ctx_list_mutex, &once_var);
#endif
	pthread_mutex_lock(&ctx_list_mutex);
	c->next = CTX_LIST;
	CTX_LIST = c;
	pthread_mutex_unlock(&ctx_list_mutex);
}

static void ctx_del(struct evsocket_ctx *delme)
{
	pthread_mutex_lock(&ctx_list_mutex);
	struct evsocket_ctx *p = NULL, *c  = CTX_LIST;
	while(c) {
		if (c == delme) {
			if (p) {
				p->next = c->next;
			} else {
				CTX_LIST = NULL;
			}
			goto out;
		}

		p = c;
		c = c->next;
	}
out:
    pthread_mutex_unlock(&ctx_list_mutex);
}

struct evsocket_event *evsocket_addevent(struct evsocket_ctx *ctx, int fd, short events,
	void (*callback)(struct evsocket_ctx *ctx, int fd, short revents, void *arg),
	void (*err_callback)(struct evsocket_ctx *ctx, int fd, short revents, void *arg),
	void *arg)
{
	struct evsocket_event *e;

	if (!ctx) {
		return NULL;
	}

	e = malloc(sizeof(struct evsocket_event));
	if (!e) {
		return e;
	}

	e->fd = fd;
	e->events = events;
	e->callback = callback;
	e->err_callback = err_callback;
	e->arg = arg;

	ctx->changed = 1;

	e->next = ctx->events;
	ctx->events = e;
	ctx->n_events++;
	return e;
}

void evsocket_delevent(struct evsocket_ctx *ctx, struct evsocket_event *e)
{
	struct evsocket_event *cur, *prev;

	if (!ctx) {
		return;
	}

	ctx->changed = 1;
	cur = ctx->events;
	prev = NULL;

	while(cur) {
		if (cur == e) {
			if (!prev) {
				ctx->events = e->next;
			} else {
				prev->next = e->next;
			}

			free(e);
			break;
		}

		prev = cur;
		cur = cur->next;
	}
	ctx->n_events--;
}


static void rebuild_poll(struct evsocket_ctx *ctx)
{
	struct evsocket_event *e;
	void *ptr = NULL;

	if (!ctx) {
		return;
	}

	if (ctx->pfd) {
		ptr = ctx->pfd;
		ctx->pfd = NULL;
		free(ptr);
	}
	if (ctx->_array) {
		ptr = ctx->_array;
		ctx->_array = NULL;
		free(ptr);
	}

	if (ctx->n_events > 0) {
		ctx->pfd = malloc(sizeof(struct pollfd) * ctx->n_events);
		ctx->_array = calloc(sizeof(struct evsocket_event), ctx->n_events);
	}

	if ((!ctx->pfd) || (!ctx->_array)) {
		/* TODO: notify error, events are disabled.
		 * perhaps provide a context-wide callback for errors.
		 */
		if (ctx->n_events > 0) {
			rist_log_priv3( RIST_LOG_ERROR, "libevsocket, rebuild_poll: events are disabled (%d)\n",
				ctx->n_events);
		}

		ctx->n_events = 0;
		ctx->changed = 0;
		return;
	}

	int i = 0;
	e = ctx->events;
	while(e) {
		memcpy(ctx->_array + i, e, sizeof(struct evsocket_event));
		ctx->pfd[i].fd = e->fd;
		ctx->pfd[i++].events = (e->events & (POLLIN | POLLOUT)) | (POLLHUP | POLLERR);
		e = e->next;
	}

	ctx->last_served = 1;
	ctx->changed = 0;
}


static void serve_event(struct evsocket_ctx *ctx, int n)
{
	struct evsocket_event *e = ctx->_array + n;

	if (!ctx) {
		return;
	}

	if (n >= ctx->n_events) {
		rist_log_priv3( RIST_LOG_ERROR, "libevsocket, serve_event: Invalid event %d >= %d\n",
			n, ctx->n_events);
		return;
	}

	if (e) {
		ctx->last_served = n;
		if ((ctx->pfd[n].revents & (POLLHUP | POLLERR)) && e->err_callback)
			e->err_callback(ctx, e->fd, ctx->pfd[n].revents, e->arg);
		else if (e->callback) {
			e->callback(ctx, e->fd, ctx->pfd[n].revents, e->arg);
		}
	}
}


/*** PUBLIC API ***/

struct evsocket_ctx *evsocket_create(void)
{
	struct evsocket_ctx *ctx;

	pthread_mutex_init(&ctx_list_mutex, NULL);

	ctx = calloc(1, sizeof(struct evsocket_ctx));
	if (!ctx) {
		return NULL;
	}

	ctx->giveup = 0;
	ctx->n_events = 0;
	ctx->changed = 0;
	ctx_add(ctx);
	return ctx;
}

void evsocket_loop(struct evsocket_ctx *ctx, int timeout)
{
	/* main loop */
	for(;;) {
		if (!ctx || ctx->giveup)
			break;
		evsocket_loop_single(ctx, timeout, 10);
	}
}

int evsocket_loop_single(struct evsocket_ctx *ctx, int timeout, int max_events)
{
	int pollret, i;
	int event_count = 0;
	int retval = 0;

	if (!ctx || ctx->giveup) {
		retval = -1;
		goto loop_error;
	}

	if (ctx->changed) {
		//rist_log_priv3( RIST_LOG_DEBUG, "libevsocket, evsocket_loop_single: rebuild poll\n");
		rebuild_poll(ctx);
	}

	if (ctx->pfd == NULL) {
		//rist_log_priv3( RIST_LOG_DEBUG, "libevsocket, evsocket_loop_single: ctx->pfd is null, no events?\n");
		ctx->changed = 1;
		retval = -2;
		goto loop_error;
	}

	if (ctx->n_events < 1) {
		rist_log_priv3( RIST_LOG_ERROR, "libevsocket, evsocket_loop_single: no events (%d)\n",
			ctx->n_events);
		retval = -3;
		goto loop_error;
	}

	pollret = poll(ctx->pfd, ctx->n_events, timeout);
	if (pollret <= 0) {
		if (pollret < 0) {
			rist_log_priv3( RIST_LOG_ERROR, "libevsocket, evsocket_loop: poll returned %d, n_events = %d, error = %d\n",
				pollret, ctx->n_events, errno);
			retval = -4;
			goto loop_error;
		}
		// No events, regular timeout
		return 0;
	}

	for (i = ctx->last_served +1; i < ctx->n_events; i++) {
		if (ctx->pfd[i].revents != 0) {
			serve_event(ctx, i);
			if (max_events > 0 && ++event_count >= max_events)
				return 0;
		}
	}

	for (i = 0; i <= ctx->last_served; i++) {
		if (ctx->pfd[i].revents != 0) {
			serve_event(ctx, i);
			if (max_events > 0 && ++event_count >= max_events)
				return 0;
		}
	}

	return 0;

loop_error:
	if (timeout > 0)
		usleep(timeout * 1000);
	return retval;
}

void evsocket_destroy(struct evsocket_ctx *ctx)
{
	ctx_del(ctx);
	if (ctx->pfd)
		free(ctx->pfd);
	if (ctx->_array)
		free(ctx->_array);
	free(ctx);
	ctx = NULL;
}

void evsocket_loop_stop(struct evsocket_ctx *ctx)
{
	if (ctx)
		ctx->giveup = 1;
}

int evsocket_geteventcount(struct evsocket_ctx *ctx)
{
	if (ctx)
		return ctx->n_events;
	else
		return 0;
}
