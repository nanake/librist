/* librist. Copyright 2019 SipRadius LLC. All right reserved.
 * Author: Daniele Lacamera <root@danielinux.net>
 * Author: Sergio Ammirata, Ph.D. <sergio@ammirata.net>
 */

#include "common.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>

#ifdef _WIN32

	/* Winsock FD_SET uses FD_SETSIZE in its expansion */
#ifdef FD_SETSIZE
/* Too late for #undef FD_SETSIZE to work: fd_set is already defined. */
# error Header inclusion order compromised!
#endif
#define FD_SETSIZE 0

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

#undef FD_SETSIZE
#define FD_SETSIZE (nfds)

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

			/* With POSIX, FD_SET & FD_ISSET are not defined if fd is negative or
			 * bigger or equal than FD_SETSIZE. That is one of the reasons why VLC
			 * uses poll() rather than select(). Most POSIX systems implement
			 * fd_set has a bit field with no sanity checks. This is especially bad
			 * on systems (such as BSD) that have no process open files limit by
			 * default, such that it is quite feasible to get fd >= FD_SETSIZE.
			 * The next instructions will result in a buffer overflow if run on
			 * a POSIX system, and the later FD_ISSET would perform an undefined
			 * memory read.
			 *
			 * With Winsock, fd_set is a table of integers. This is awfully slow.
			 * However, FD_SET and FD_ISSET silently and safely discard excess
			 * entries. Here, overflow cannot happen anyway: fd_set of adequate
			 * size are allocated.
			 * Note that Vista has a much nicer WSAPoll(), but Mingw does not
			 * support it yet.
			 */
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

#ifndef HAVE_ALERTABLE_SELECT
		//# warning FIXME!Fix cancellation and remove this crap.
		if ((timeout < 0) || (timeout > 50)) {
			tv.tv_sec = 0;
			tv.tv_usec = 50000;
		} else
#endif
		if (timeout >= 0) {
			div_t d = div(timeout, 1000);
			tv.tv_sec = d.quot;
			tv.tv_usec = d.rem * 1000;
		}

		val = select(val + 1, rdset, wrset, exset, /*(timeout >= 0) ?*/ &tv /*: NULL*/);

#ifndef HAVE_ALERTABLE_SELECT
		if (val == 0) {
			if (timeout > 0) {
				timeout -= (timeout > 50) ? 50 : timeout;
			}

			if (timeout != 0) {
				goto resume;
			}
		}
#endif

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
			perror("MEMORY");
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

struct evsocket_ctx *evsocket_init(void)
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


void evsocket_loop(struct evsocket_ctx *ctx)
{
	int pollret, i;
	for(;;) {
		if (!ctx || ctx->giveup)
			break;

		if (ctx->changed) {
			rebuild_poll(ctx);
			continue;
		}

		if (ctx->pfd == NULL) {
			//sleep_ms(1000);
			ctx->changed = 1;
			continue;
		}

		if (ctx->n_events < 1) {
			continue;
		}

		pollret = poll(ctx->pfd, ctx->n_events, 3600 * 1000);
		if (pollret <= 0) {
			continue;
		}

		for (i = ctx->last_served +1; i < ctx->n_events; i++) {
			if (ctx->pfd[i].revents != 0) {
				serve_event(ctx, i);
				goto end_loop;
			}
		}

		for (i = 0; i <= ctx->last_served; i++) {
			if (ctx->pfd[i].revents != 0) {
				serve_event(ctx, i);
				goto end_loop;
			}
		}
	end_loop:
		continue;

	} /* main loop */
	ctx_del(ctx);
	ctx = NULL;
}

void evsocket_loop_single(struct evsocket_ctx *ctx, int timeout)
{
	int pollret, i;

	if (!ctx || ctx->giveup) {
		return;
	}

	if (ctx->changed) {
		rebuild_poll(ctx);
		return;
	}

	if (ctx->pfd == NULL) {
		ctx->changed = 1;
		return;
	}

	if (ctx->n_events < 1) {
		return;
	}

	pollret = poll(ctx->pfd, ctx->n_events, timeout);
	if (pollret <= 0) {
		if (pollret < 0) {
			fprintf(stderr, "error: pollret returned %d, n_events = %d, error = %d\n", pollret, ctx->n_events, errno);
		} else {
			// is additional sleep needed? yes, or the calling up can become unresponsive and the CPU maxed out
			// TODO: getlasterror and check if additional sleep is needed
		}

		return;
	}

	for (i = ctx->last_served +1; i < ctx->n_events; i++) {
		if (ctx->pfd[i].revents != 0) {
			serve_event(ctx, i);
			return;
		}
	}

	for (i = 0; i <= ctx->last_served; i++) {
		if (ctx->pfd[i].revents != 0) {
			serve_event(ctx, i);
			return;
		}
	}
}

void evsocket_loop_finalize(struct evsocket_ctx *ctx)
{
	ctx_del(ctx);
	if (ctx->pfd)
		free(ctx->pfd);
	if (ctx->_array)
		free(ctx->_array);
	free(ctx);
}

void evsocket_fini(struct evsocket_ctx *ctx)
{
	ctx->giveup = 1;
}
