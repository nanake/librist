/* librist. Copyright 2019 SipRadius LLC. All right reserved.
 * Author: Daniele Lacamera <root@danielinux.net>
 * Author: Sergio Ammirata, Ph.D. <sergio@ammirata.net>
 */

#ifndef __LIBEVSOCKET
#define __LIBEVSOCKET

#include "common.h"

#ifdef _WIN32
# include <winsock2.h>
# include <ws2tcpip.h>
#else
# include <poll.h>
#endif

#define EVSOCKET_EV_READ POLLIN
#define EVSOCKET_EV_WRITE POLLOUT

struct evsocket_event;
struct evsocket_ctx;

RIST_PRIV struct evsocket_ctx *evsocket_init(void);
RIST_PRIV void evsocket_loop(struct evsocket_ctx *ctx);
RIST_PRIV void evsocket_loop_single(struct evsocket_ctx *ctx, int timeout);
RIST_PRIV void evsocket_loop_finalize(struct evsocket_ctx *ctx);
RIST_PRIV void evsocket_fini(struct evsocket_ctx *ctx);
RIST_PRIV struct evsocket_event *evsocket_addevent(struct evsocket_ctx *ctx, int fd, short events,
			void (*callback)(struct evsocket_ctx *ctx, int fd, short revents, void *arg),
			void (*err_callback)(struct evsocket_ctx *ctx, int fd, short revents, void *arg),
			void *arg);

RIST_PRIV void evsocket_delevent(struct evsocket_ctx *ctx, struct evsocket_event *e);

#endif

