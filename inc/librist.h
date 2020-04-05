/* librist. Copyright 2019 SipRadius LLC. All right reserved.
 * Author: Kuldeep Singh Dhaka <kuldeep@madresistor.com>
 * Author: Sergio Ammirata, Ph.D. <sergio@ammirata.net>
 */

#ifndef LIBRIST_H
#define LIBRIST_H

/* Track PROTOCOL and API changes */
#define RIST_PROTOCOL_VERSION (2)
#define RIST_API_VERSION (4)
#define RIST_SUBVERSION (5)

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

struct rist_output_buffer {
	struct rist_peer *peer;
	uint32_t flow_id;
	void *payload;
	size_t payload_len;
	uint16_t src_port;
	uint16_t dst_port;
	uint64_t timestamp_ntp;
	uint32_t flags;
};

struct rist_peer_config {
	const char *address;
	uint16_t gre_dst_port;

	/* Recovery options */
	enum rist_recovery_mode recovery_mode;
	uint32_t recovery_maxbitrate;
	uint32_t recovery_maxbitrate_return;
	uint32_t recovery_length_min;
	uint32_t recovery_length_max;
	uint32_t recovery_reorder_buffer;
	uint32_t recovery_rtt_min;
	uint32_t recovery_rtt_max;
	uint32_t weight;

	enum rist_buffer_bloat_mode buffer_bloat_mode;
	uint32_t buffer_bloat_limit;
	uint32_t buffer_bloat_hard_limit;
};

/**
 * @brief Create Client
 *
 * Create a RIST client instance
 *
 * @param[out] ctx a context representing the client instance
 * @param flow_id Flow ID
 * @param profile RIST profile
 * @param loglevel Level of log messages to display
 * @return 0 on success, -1 in case of error.
 */
RIST_API int rist_client_create(struct rist_client **ctx, enum rist_profile profile,
				uint32_t flow_id, enum rist_log_level log_level);

 /**
 * @brief Assign dynamic authentiation handler
 *
 * Whenever a new peer is connected, @a conn_cb is called.
 * Whenever a new peer is disconnected, @a disconn_cb is called.
 *
 * @param conn_cb A pointer to the function that will be called when a new peer
 * connects. Return 1 or 0 to authorize or decline (NULL function pointer is valid)
 * @param disconn_cb A pointer to the function that will be called when a new peer
 * is marked as dead (NULL function pointer is valid)
 * @param arg is an the extra argument passed to the `conn_cb` and `disconn_cb`
 */
RIST_API int rist_client_auth_handler_set(struct rist_client *ctx,
		int (*connect_cb)(void *arg, char* connecting_ip, uint16_t connecting_port, char* local_ip, uint16_t local_port, struct rist_peer *peer),
		void (*disconn_cb)(void *arg, struct rist_peer *peer),
		void *arg);

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
RIST_API int rist_client_cname_set(struct rist_client *ctx, const void *cname, size_t cname_len);

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
RIST_API int rist_client_peer_add(struct rist_client *ctx,
		const struct rist_peer_config *config, struct rist_peer **peer);

/**
 * @brief Remove a peer connector to the existing client.
 *
 * @param a RIST client context
 * @param peer a pointer to the struct rist_peer, which
 *        points to the peer endpoint.
 * @return 0 on success, -1 in case of error.
 */
RIST_API int rist_client_peer_del(struct rist_client *ctx,
		struct rist_peer *peer);

/**
 * @brief Enable encryption
 *
 * Call after client initialization to enable encryption.
 *
 * @param a RIST client context
 * @param secret Pre-shared passphrase
 * @param key_size size of the key used for the encryption
 * @return 0 on success, -1 on error
 */
RIST_API int rist_client_encrypt_aes_set(struct rist_client *ctx,
		const char *secret, int key_size);

/**
 * @brief Set RIST retry timeout
 *
 * Set time interleaving retries during the protocol handshake
 *
 * @param a RIST client context
 * @param t timeout in ms
 * @return never
 */
RIST_API int rist_client_session_timeout_set(struct rist_client *ctx, int t);

/**
 * @brief Set RIST keep-alive timeout
 *
 * Set keep-alive timeout
 *
 * @param a RIST client context
 * @param t timeout in ms
 * @return never
 */
RIST_API int rist_client_keepalive_timeout_set(struct rist_client *ctx, int t);

/**
 * @brief Set RIST max jitter
 *
 * Set max jitter
 *
 * @param a RIST client context
 * @param t max jitter in ms
 * @return 0 on success, -1 on error
 */
RIST_API int rist_client_max_jitter_set(struct rist_client *ctx, int t);

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
RIST_API int rist_client_oob_set(struct rist_client *ctx, 
		void (*oob_data_callback)(void *arg, struct rist_peer *peer, const void *buffer, size_t len),
		void *arg);

/**
 * @brief Enable compression
 *
 * Call after client initialization to enable compression.
 *
 * @param a RIST client context
 * @param compression, 0 for disabled, 1 for enabled
 * @return 0 on success, -1 on error
 */
RIST_API int rist_client_compression_lz4_set(struct rist_client *ctx, int compression);

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
RIST_API int rist_client_oob_write(struct rist_client *ctx, struct rist_peer *peer, const void *buf, size_t len);

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
RIST_API int rist_client_data_write(struct rist_client *ctx, const void *buf, size_t len, uint16_t src_port, uint16_t dst_port);

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
RIST_API int rist_client_data_timed_write(struct rist_client *ctx, const void *buf, size_t len, uint16_t src_port, uint16_t dst_port, uint64_t ntp_time);

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
 * @brief Destroy RIST client
 *
 * Destroy the RIST instance
 *
 * @param a RIST client context
 * @return 0 on success, -1 on error
 */
RIST_API int rist_client_destroy(struct rist_client *ctx);

/**
 * Create a RIST server instance
 *
 * @param[out] ctx a context representing the server instance
 * @param profile RIST profile
 * @param listen_addr Address to listen to, can be NULL to indicate ANY
 * @param loglevel Level of log messages to display
 * @return 0 on success, -1 on error
 */
RIST_API int rist_server_create(struct rist_server **ctx, enum rist_profile profile,
			const struct rist_peer_config *default_peer_config,
			enum rist_log_level log_level);
 
/**
 * @brief Assign dynamic authentiation handler
 *
 * Whenever a new peer is connected, @a conn_cb is called.
 * Whenever a new peer is disconnected, @a disconn_cb is called.
 *
 * @param conn_cb A pointer to the function that will be called when a new peer
 * connects. Return 1 or 0 to authorize or decline (NULL function pointer is valid)
 * @param disconn_cb A pointer to the function that will be called when a new peer
 * is marked as dead (NULL function pointer is valid)
 * @param arg is an the extra argument passed to the `conn_cb` and `disconn_cb`
 */
RIST_API int rist_server_auth_handler_set(struct rist_server *ctx,
		int (*connect_cb)(void *arg, char* connecting_ip, uint16_t connecting_port, char* local_ip, uint16_t local_port, struct rist_peer *peer),
		void (*disconn_cb)(void *arg, struct rist_peer *peer),
		void *arg);

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
RIST_API int rist_server_cname_set(struct rist_server *ctx, const void *cname, size_t cname_len);

/**
 * @brief Add a peer connector to the existing server.
 *
 * One server can receive data from multiple peers.
 *
 * @param a RIST client context
 * @param listen_addr Address to listen to, can be NULL to indicate ANY
 * @return 0 on success, -1 on error
 */
RIST_API int rist_server_peer_add(struct rist_server *ctx, const char *listen_addr);

/**
 * @brief Remove a peer connector to the existing server.
 *
 * @param a RIST server context
 * @param peer a pointer to the struct rist_peer, which
 *        points to the peer endpoint.
 * @return 0 on success, -1 in case of error.
 */
RIST_API int rist_server_peer_del(struct rist_server *ctx,
		struct rist_peer *peer);

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
RIST_API int rist_server_encrypt_aes_set(struct rist_server *ctx, const char *secret, int key_size);

/**
 * @brief Set RIST retry timeout
 *
 * Set time interleaving retries during the protocol handshake
 *
 * @param a RIST server context
 * @param t timeout in ms
 * @return 0 on success, -1 on error
 */
RIST_API int rist_server_session_timeout_set(struct rist_server *ctx, int t);

/**
 * @brief Set RIST keep-alive timeout
 *
 * Set keep-alive timeout
 *
 * @param a RIST server context
 * @param t timeout in ms
 * @return 0 on success, -1 on error
 */
RIST_API int rist_server_keepalive_timeout_set(struct rist_server *ctx, int t);

/**
 * @brief Set RIST max jitter
 *
 * Set max jittter
 *
 * @param a RIST server context
 * @param t max jitter in ms
 * @return 0 on success, -1 on error
 */
RIST_API int rist_server_max_jitter_set(struct rist_server *ctx, int t);

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
RIST_API int rist_server_oob_set(struct rist_server *ctx, 
		void (*oob_data_callback)(void *arg, struct rist_peer *peer, const void *buffer, size_t len),
		void *arg);

/**
 * @brief Configure nack type
 *
 * Choose the nack tyoe used by the server. This function returns immediately.
 *
 * @param a RIST server context
 * @param nack_type 0 for range (default), 1 for bitmask
 * @return immediately
 */
RIST_API int rist_server_nack_type_set(struct rist_server *ctx, enum rist_nack_type nacks_type);

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
	void (*receive_callback)(void *arg, struct rist_peer *peer, uint32_t flow_id, const void *buffer, size_t len, uint16_t src_port, uint16_t dst_port, uint64_t timestamp_ntp, uint32_t flags),
	void *arg);

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
RIST_API int rist_server_oob_write(struct rist_server *ctx, struct rist_peer *peer, const void *buf, size_t len);

/**
 * @brief Reads rist data
 *
 * Use this API to read data from an internal fifo queue instead of the callback
 *
 * @param a RIST server context
 * @return a pointer to the rist_output_buffer structure
 */
RIST_API struct rist_output_buffer *rist_server_data_read(struct rist_server *ctx);

/**
 * @brief Destroy RIST server
 *
 * Destroy RIST server instance
 *
 * @param a RIST server context
 * @return 0 on success, -1 on error
 */
RIST_API int rist_server_destroy(struct rist_server *ctx);

__END_DECLS

#endif
