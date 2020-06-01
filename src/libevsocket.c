/* librist. Copyright 2019 SipRadius LLC. All right reserved.
 * Author: Daniele Lacamera <root@danielinux.net>
 * Author: Sergio Ammirata, Ph.D. <sergio@ammirata.net>
 */

#include "common/attributes.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include "log-private.h"

#ifdef _WIN32

#if !defined(UNDER_CE)
# define _NO_OLDNAMES 1
# include <io.h>
#endif

#include <winsock2.h>
#include <ws2tcpip.h>

static int poll(struct pollfd *fds, unsigned nfds, int timeout)
{
	size_t setsize = sizeof(fd_set) + nfds * sizeof(SOCKET);
	fd_set *rdset = malloc(setsize);
	fd_set *wrset = malloc(setsize);
	fd_set *exset = malloc(setsize);
	struct timeval tv = { 0, 0 };
	int val;

	if (RIST_UNLIKELY(rdset == NULL || wrset == NULL || exset == NULL)) {
		free(rdset);
		free(wrset);
		free(exset);
		errno = ENOMEM;
		return -1;
	}

	resume:
		val = -1;

		FD_ZERO(rdset);
		FD_ZERO(wrset);
		FD_ZERO(exset);
		for (unsigned i = 0; i < nfds; i++) {
			int fd = fds[i].fd;
			if (val < fd) {
				val = fd;
			}

			if (fds[i].events & POLLIN) {
				FD_SET((SOCKET)fd, rdset);
			}

			if (fds[i].events & POLLOUT) {
				FD_SET((SOCKET)fd, wrset);
			}

			if (fds[i].events & POLLPRI) {
				FD_SET((SOCKET)fd, exset);
			}
		}

		if ((timeout < 0) || (timeout > 50)) {
			tv.tv_sec = 0;
			tv.tv_usec = 50000;
		} else if (timeout >= 0) {
			div_t d = div(timeout, 1000);
			tv.tv_sec = d.quot;
			tv.tv_usec = d.rem * 1000;
		}

		val = select(val + 1, rdset, wrset, exset, /*(timeout >= 0) ?*/ &tv /*: NULL*/);

		if (val == 0) {
			if (timeout > 0) {
				timeout -= (timeout > 50) ? 50 : timeout;
			}

			if (timeout != 0) {
				goto resume;
			}
		}

		if (val == -1) {
			return -1;
		}

		for (unsigned i = 0; i < nfds; i++) {
			int fd = fds[i].fd;
			fds[i].revents = (FD_ISSET(fd, rdset) ? POLLIN : 0)
					| (FD_ISSET(fd, wrset) ? POLLOUT : 0)
					| (FD_ISSET(fd, exset) ? POLLPRI : 0);
		}
		free(exset);
		free(wrset);
		free(rdset);
		return val;
}

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

static pthread_mutex_t ctx_list_mutex;
static struct evsocket_ctx *CTX_LIST = NULL;

static void ctx_add(struct evsocket_ctx *c)
{
	pthread_mutex_lock(&ctx_list_mutex);
	c->next = CTX_LIST;
	CTX_LIST = c;
	pthread_mutex_unlock(&ctx_list_mutex);
}

static void ctx_del(struct evsocket_ctx *delme)
{
	struct evsocket_ctx *p = NULL, *c  = CTX_LIST;
	while(c) {
		if (c == delme) {
			pthread_mutex_lock(&ctx_list_mutex);
			if (p) {
				p->next = c->next;
			} else {
				CTX_LIST = NULL;
			}

			pthread_mutex_unlock(&ctx_list_mutex);
			return;
		}

		p = c;
		c = c->next;
	}
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
		ctx->_array = malloc(sizeof(struct evsocket_event) * ctx->n_events);
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

	ctx->last_served = 0;
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
		else {
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
