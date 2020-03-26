/* librist. Copyright 2019 SipRadius LLC. All right reserved.
 * Author: Kuldeep Singh Dhaka <kuldeep@madresistor.com>
 * Author: Sergio Ammirata, Ph.D. <sergio@ammirata.net>
 */

#ifndef LIBRIST_H
#define LIBRIST_H

/* Track PROTOCOL and API changes */
#define RIST_PROTOCOL_VERSION (2)
#define RIST_API_VERSION (3)
#define RIST_SUBVERSION (4)

#include <stdint.h>
#include <stdlib.h>

/* __BEGIN_DECLS should be used at the beginning of your declarations,
   so that C++ compilers don't mangle their names.  Use __END_DECLS at
   the end of C declarations. */
#undef __BEGIN_DECLS
#undef __END_DECLS
#ifdef __cplusplus
# define __BEGIN_DECLS extern "C" {
# define __END_DECLS }
#else
# define __BEGIN_DECLS /* empty */
# define __END_DECLS /* empty */
#endif

/* Reference: http://gcc.gnu.org/wiki/Visibility */
#if defined(_WIN32) || defined(__CYGWIN__)
# if defined(rist_EXPORTS)
#  if defined(__GNUC__)
#   define RIST_API __attribute__ ((dllexport))
#  else /* defined(__GNUC__) */
			/* Note: actually gcc seems to also supports this syntax. */
#   define RIST_API __declspec(dllexport)
#  endif /* defined(__GNUC__) */
# else /* defined(rist_EXPORTS) */
#  if defined(__GNUC__)
#   define RIST_API __attribute__ ((dllimport))
#  else
			/* Note: actually gcc seems to also supports this syntax. */
#   define RIST_API __declspec(dllimport)
#  endif
# endif /* defined(rist_EXPORTS) */
#else /* defined(_WIN32) || defined(__CYGWIN__) */
	#if __GNUC__ >= 4
		#define RIST_API __attribute__ ((visibility ("default")))
# else /* __GNUC__ >= 4 */
		#define RIST_API
# endif /* __GNUC__ >= 4 */
#endif /* defined(_WIN32) || defined(__CYGWIN__) */

__BEGIN_DECLS

enum rist_nack_type {
	RIST_NACK_RANGE = 0,
	RIST_NACK_BITMASK = 1,
};

enum rist_profile {
	RIST_PROFILE_SIMPLE = 0,
	RIST_PROFILE_MAIN = 1,
	RIST_PROFILE_ADVANCED = 2,
};

enum rist_log_level {
	RIST_LOG_QUIET = -1,
	RIST_LOG_INFO = 0,
	RIST_LOG_ERROR = 1,
	RIST_LOG_WARN = 2,
	RIST_LOG_DEBUG = 3,
	RIST_LOG_SIMULATE = 4,
};

enum rist_recovery_mode {
	RIST_RECOVERY_MODE_UNCONFIGURED = 0,
	RIST_RECOVERY_MODE_DISABLED = 1,
	RIST_RECOVERY_MODE_BYTES = 2,
	RIST_RECOVERY_MODE_TIME = 3,
};

enum rist_buffer_bloat_mode {
	RIST_BUFFER_BLOAT_MODE_OFF = 0,
	RIST_BUFFER_BLOAT_MODE_NORMAL = 1,
	RIST_BUFFER_BLOAT_MODE_AGGRESSIVE = 2
};

struct rist_server;
struct rist_client;
struct rist_peer;

struct rist_peer_config {
	const char *address;
	uint16_t gre_dst_port;

	/* Recovery options */
	enum rist_recovery_mode recovery_mode;
	uint32_t recovery_maxbitrate;
	uint32_t recovery_maxbitrate_return;
	uint32_t recovery_length_min;
	uint32_t recovery_length_max;
	uint32_t recover_reorder_buffer;
	uint32_t recovery_rtt_min;
	uint32_t recovery_rtt_max;
	uint32_t weight;

	enum rist_buffer_bloat_mode bufferbloat_mode;
	uint32_t bufferbloat_limit;
	uint32_t bufferbloat_hard_limit;
};

/**
 * @brief Create Client
 *
 * Create a RIST client instance
 *
 * @param[out] ctx a context representing the client instance
 * @return 0 on success, -1 in case of error.
 */
RIST_API int rist_client_create(struct rist_client **ctx, enum rist_profile profile);

/**
 * @brief Configure the SDES CName
 *
 * This allows you to override the auto-generated SDES CName
 *
 * @param a RIST client context
 * @param cname data to be sent through librist
 * @param cname_len size of cname buffer
 * @return 0 on success, -1 on error
 */
RIST_API int rist_client_set_cname(struct rist_client *ctx, const void *cname, size_t cname_len);

/**
 * @brief Destroy RIST client
 *
 * Destroy a RIST client instance
 *
 * @return a context representing the client instance
 */
RIST_API int rist_client_destroy(struct rist_client *ctx);

/**
 * @brief Initialize Client
 *
 * Client is initialized and waiting to add peers.
 *
 * @param a RIST client context
 * @param flow_id Flow ID
 * @param loglevel Level of log messages to display
 * @param auth_connect_callback A pointer to the function that will be called when a new peer
 * connects. Return 1 or 0 to authorize or decline (NULL function pointer is valid)
 * @param auth_disconnect_callback A pointer to the function that will be called when a new peer
 * is marked as dead (NULL function pointer is valid)
 * @param arg is an the extra argument passed to the `auth_connect_callback` and `auth_disconnect_callback`
 * @return 0 on success, -1,-2, or -3 in case of error.
 */
RIST_API int rist_client_init(struct rist_client *ctx,
		uint32_t flow_id, enum rist_log_level log_level,
		int (*auth_connect_callback)(void *arg, char* connecting_ip, uint16_t connecting_port, char* local_ip, uint16_t local_port, struct rist_peer *peer),
		void (*auth_disconnect_callback)(void *arg, struct rist_peer *peer),
		void *arg);

/**
 * @brief Add a peer connector to the existing client.
 *
 * One client can send data to multiple peers.
 *
 * @param a RIST client context
 * @param config a pointer to the struct rist_peer_config, which contains
 *        the configuration parameters for the peer endpoint.
 * @param[out] peer Store the new peer pointer
 * @return 0 on success, -1 in case of error.
 */
RIST_API int rist_client_add_peer(struct rist_client *ctx,
		const struct rist_peer_config *config, struct rist_peer **peer);

/**
 * @brief Remove a peer connector to the existing client.
 *
 * @param a RIST client context
 * @param peer a pointer to the struct rist_peer, which
 *        points to the peer endpoint.
 * @return 0 on success, -1 in case of error.
 */
RIST_API int rist_client_remove_peer(struct rist_client *ctx,
		struct rist_peer *peer);

/**
 * @brief Kickstart a pre-configured client
 *
 * After all the peers have been added, this function triggers
 * the client to start
 *
 * @param a RIST client context
 * @return 0 on success, -1 in case of error.
 */
RIST_API int rist_client_start(struct rist_client *ctx);

/**
 * @brief Write data into a librist packet.
 *
 * One client can send write data into a librist packet.
 *
 * @param a RIST client context
 * @param buf data to be sent through librist
 * @param len size of buf buffer
 * @return number of written bytes on success, -1 in case of error.
 */
RIST_API int rist_client_write(struct rist_client *ctx, const void *buf, size_t len, uint16_t src_port, uint16_t dst_port);

/**
 * @brief Write data into a librist packet.
 *
 * One client can send write data into a librist packet.
 *
 * @param a RIST client context
 * @param buf data to be sent through librist
 * @param len size of buf buffer
 * @param ntp_time 64 bit timestamp in NTP format
 * @return number of written bytes on success, -1 in case of error.
 */
RIST_API int rist_client_write_timed(struct rist_client *ctx, const void *buf, size_t len, uint16_t src_port, uint16_t dst_port, uint64_t ntp_time);

/**
 * @brief Write data directly to a remote server peer.
 *
 * This API is used to transmit out-of-band data to a remote server peer
 *
 * @param a RIST client context
 * @param peer a pointer to the struct rist_peer, which
 *        points to the peer endpoint.
 * @param buf data to be sent through a librist peer connection
 * @param len size of buf buffer (IP header is expected by non-librist counterparts)
 * @return number of written bytes on success, -1 in case of error.
 */
RIST_API int rist_client_write_oob(struct rist_client *ctx, struct rist_peer *peer, const void *buf, size_t len);

/**
 * @brief Set RIST retry timeout
 *
 * Set time interleaving retries during the protocol handshake
 *
 * @param a RIST client context
 * @param t timeout in ms
 * @return never
 */
RIST_API int rist_client_set_session_timeout(struct rist_client *ctx, int t);

/**
 * @brief Set RIST keep-alive timeout
 *
 * Set keep-alive timeout
 *
 * @param a RIST client context
 * @param t timeout in ms
 * @return never
 */
RIST_API int rist_client_set_keepalive_timeout(struct rist_client *ctx, int t);

/**
 * @brief Set RIST max jitter
 *
 * Set max jitter
 *
 * @param a RIST client context
 * @param t max jitter in ms
 * @return 0 on success, -1 on error
 */
RIST_API int rist_client_set_max_jitter(struct rist_client *ctx, int t);

/**
 * @brief Enable encryptionrist_client_create
 *
 * Call after client initialization to enable encryption.
 *
 * @param a RIST client context
 * @param secret Pre-shared passphrase
 * @param key_size size of the key used for the encryption
 * @return 0 on success, -1 on error
 */
RIST_API int rist_client_encrypt_enable(struct rist_client *ctx,
		const char *secret, int key_size);

/**
 * @brief Enable out-of-band data channel
 *
 * Call after server initialization to enable out-of-band data.
 *
 * @param a RIST client context
 * @param oob_data_callback A pointer to the function that will be called when out-of-band data
 * comes in (NULL function pointer is valid)
 * @param arg is an the extra argument passed to the `oob_data_callback`
 * @return 0 on success, -1 on error
 */
RIST_API int rist_client_oob_enable(struct rist_client *ctx, 
		void (*oob_data_callback)(void *arg, struct rist_peer *peer, const void *buffer, size_t len),
		void *arg);

/**
 * @brief Enable compression
 *
 * Call after client initialization to enable encryption.
 *
 * @param a RIST client context
 * @param compression, 0 for disabled, 1 for enabled
 * @return 0 on success, -1 on error
 */
RIST_API int rist_client_compress_enable(struct rist_client *ctx, int compression);

/**
 * @brief Disconnect a client peer
 *
 * Disconnects a connected server peer or a client bound peer
 *
 * @param a RIST client context
 * @param peer a pointer to the struct rist_peer, which
 *        points to the peer endpoint.
 * @return 0 on success, -1 on error
 */
RIST_API int rist_client_disconnect_peer(struct rist_client *ctx, struct rist_peer *peer);

/**
 * @brief Shutdown RIST client
 *
 * Shutdown the RIST instance
 *
 * @param a RIST client context
 * @return 0 on success, -1 on error
 */
RIST_API int rist_client_shutdown(struct rist_client *ctx);

/**
 * @brief Set custom file descriptor to be used for printing stats
 *
 * Set fd to print librist statistics
 *
 * @param fd file descriptor to be used for
 *        for statistics
 *
 * @return 0 on success, -1 on error
 */
RIST_API int rist_set_stats_fd(int fd);

/**
 * @brief Set custom udp port to be used for printing stats
 *
 * Set port to print librist statistics
 *
 * @param port port to be used for statistics
 * @return 0 on success, -1 on error
 */
RIST_API int rist_set_stats_socket(int port);

/**
 * @brief Returns information about the handshake state
 *
 * Get information about the handshake
 * state, the returned string is
 * heap-allocated and must be therefore
 * freed after being used.
 *
 * @param a RIST client context
 */
RIST_API char *rist_client_get_status(struct rist_client *ctx);

/**
 * @brief Write data directly to a remote client peer.
 *
 * This API is used to transmit out-of-band data to a remote client peer
 *
 * @param a RIST server context
 * @param peer a pointer to the struct rist_peer, which
 *        points to the peer endpoint.
 * @param buf data to be sent through a librist peer connection
 * @param len size of buf buffer (IP header is expected by non-librist counterparts)
 * @return number of written bytes on success, -1 in case of error.
 */
RIST_API int rist_server_write_oob(struct rist_server *ctx, struct rist_peer *peer, const void *buf, size_t len);

/**
 * @brief Returns information about the handshake state
 *
 * Get information about the handshake
 * state, the returned string is
 * heap-allocated and must be therefore
 * freed after being used.
 *
 * @param a RIST server context
 */
RIST_API char *rist_server_get_status(struct rist_server *ctx);

/**
 * @brief Configure nack type
 *
 * Choose the nack tyoe used by the server. This function returns immediately.
 *
 * @param a RIST server context
 * @param nack_type 0 for range (default), 1 for bitmask
 * @return immediately
 */
RIST_API int rist_server_set_nack_type(struct rist_server *ctx, enum rist_nack_type nacks_type);

/**
 * @brief Create RIST Server
 *
 * Create a RIST server instance
 *
 * @param[out] ctx a context representing the server instance
 * @return 0 on success, -1 on error
 */
RIST_API int rist_server_create(struct rist_server **ctx, enum rist_profile profile);

/**
 * @brief Configure the SDES CName
 *
 * This allows you to override the auto-generated SDES CName
 *
 * @param a RIST server context
 * @param cname data to be sent through librist
 * @param cname_len size of cname buffer
 * @return 0 on success, -1 on error
 */
RIST_API int rist_server_set_cname(struct rist_server *ctx, const void *cname, size_t cname_len);

/**
 * @brief Initialize server
 *
 * Server is initialized and waiting start.
 *
 * @param a RIST server context
 * @param listen_addr Address to listen to, can be NULL to indicate ANY
 * @param loglevel Level of log messages to display
 * @param auth_connect_callback A pointer to the function that will be called when a new peer
 * connects. Return 1 or 0 to authorize or decline (NULL function pointer is valid)
 * @param auth_disconnect_callback A pointer to the function that will be called when a new peer
 * is marked as dead (NULL function pointer is valid)
 * @param arg is an the extra argument passed to the `auth_connect_callback` and `auth_disconnect_callback`
 * @return 0 on success, -1 on error
 */
RIST_API int rist_server_init(struct rist_server *ctx,
		const struct rist_peer_config *default_peer_config, enum rist_log_level log_level,
		int (*auth_connect_callback)(void *arg, char* connecting_ip, uint16_t connecting_port, char* local_ip, uint16_t local_port, struct rist_peer *peer),
		void (*auth_disconnect_callback)(void *arg, struct rist_peer *peer),
		void *arg);

/**
 * @brief Add a peer connector to the existing server.
 *
 * One server can receive data from multiple peers.
 *
 * @param a RIST client context
 * @param listen_addr Address to listen to, can be NULL to indicate ANY
 * @return 0 on success, -1 on error
 */
RIST_API int rist_server_add_peer(struct rist_server *ctx, const char *listen_addr);

/**
 * @brief Enable encryption
 *
 * Call after server initialization to enable encryption.
 *
 * @param a RIST server context
 * @param secret Pre-shared passphrase
 * @param key_size size of the key used for the encryption
 * @return 0 on success, -1 on error
 */
RIST_API int rist_server_encrypt_enable(struct rist_server *ctx, const char *secret, int key_size);

/**
 * @brief Enable out-of-band data channel
 *
 * Call after server initialization to enable out-of-band data.
 *
 * @param a RIST server context
 * @param oob_data_callback A pointer to the function that will be called when out-of-band data
 * comes in (NULL function pointer is valid)
 * @param arg is an the extra argument passed to the `oob_data_callback`
 * @return 0 on success, -1 on error
 */
RIST_API int rist_server_oob_enable(struct rist_server *ctx, 
		void (*oob_data_callback)(void *arg, struct rist_peer *peer, const void *buffer, size_t len),
		void *arg);

/**
 * @brief Setup server start
 *
 * Start server data output thread. This function returns immediately.
 *
 * @param a RIST server context
 * @param receive_callback The function that will be called when a data frame is
 * received from a client.
 * @param arg the extra argument passed to the `receive_callback`
 * @note Return immediately
 */
RIST_API int rist_server_start(struct rist_server *ctx,
	void (*receive_callback)(void *arg, struct rist_peer *peer, uint64_t flow_id, const void *buffer, size_t len, uint16_t src_port, uint16_t dst_port),
	void *arg);

/**
 * @brief Set RIST retry timeout
 *
 * Set time interleaving retries during the protocol handshake
 *
 * @param a RIST server context
 * @param t timeout in ms
 * @return 0 on success, -1 on error
 */
RIST_API int rist_server_set_session_timeout(struct rist_server *ctx, int t);

/**
 * @brief Set RIST keep-alive timeout
 *
 * Set keep-alive timeout
 *
 * @param a RIST server context
 * @param t timeout in ms
 * @return 0 on success, -1 on error
 */
RIST_API int rist_server_set_keepalive_timeout(struct rist_server *ctx, int t);

/**
 * @brief Set RIST max jitter
 *
 * Set max jittter
 *
 * @param a RIST server context
 * @param t max jitter in ms
 * @return 0 on success, -1 on error
 */
RIST_API int rist_server_set_max_jitter(struct rist_server *ctx, int t);

/**
 * @brief Disconnect a server peer
 *
 * Disconnects a connected client peer or a server bound peer
 *
 * @param a RIST server context
 * @param peer a pointer to the struct rist_peer, which
 *        points to the peer endpoint.
 * @return 0 on success, -1 on error
 */
RIST_API int rist_server_disconnect_peer(struct rist_server *ctx, struct rist_peer *peer);

/**
 * @brief Shutdown RIST server
 *
 * Shutdown RIST server instance
 *
 * @param a RIST server context
 * @return 0 on success, -1 on error
 */
RIST_API int rist_server_shutdown(struct rist_server *ctx);

__END_DECLS

#endif
