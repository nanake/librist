/* librist. Copyright 2019-2020 SipRadius LLC. All right reserved.
 * Author: Kuldeep Singh Dhaka <kuldeep@madresistor.com>
 * Author: Sergio Ammirata, Ph.D. <sergio@ammirata.net>
 */

#ifndef LIBRIST_H
#define LIBRIST_H

#ifdef __cplusplus
extern "C" {
#endif
#include <stdio.h>
#include "common.h"
#include "headers.h"
#include "logging.h"

/* Receiver specific functions, use rist_receiver_create to create a receiver rist_ctx */
/**
 * Create a RIST receiver instance
 *
 * @param[out] ctx a context representing the receiver instance
 * @param profile RIST profile
 * @param logging_settings Optional struct containing the logging settings.
 * @return 0 on success, -1 on error
 */
RIST_API int rist_receiver_create(struct rist_ctx **ctx, enum rist_profile profile,
			struct rist_logging_settings *logging_settings);

/**
 * @brief Configure nack type
 *
 * Choose the nack type used by the receiver.
 *
 * @param ctx RIST receiver context
 * @param nack_type 0 for range (default), 1 for bitmask
 * @return 0 on success, -1 on error
 */
RIST_API int rist_receiver_nack_type_set(struct rist_ctx *ctx, enum rist_nack_type nacks_type);

/**
 * @brief Reads rist data
 *
 * Use this API to read data from an internal fifo queue instead of the callback
 *
 * @param ctx RIST receiver context
 * @param[out] data_block a pointer to the rist_data_block structure
 * @param timeout How long to wait for queue data (ms), 0 for no wait
 * @return num buffers remaining on queue +1 (0 if no buffer returned), -1 on error
 */
RIST_API int rist_receiver_data_read(struct rist_ctx *ctx, const struct rist_data_block **data_block, int timeout);

/**
 * @brief Enable data callback channel
 *
 * Call to enable data callback channel.
 *
 * @param ctx RIST receiver context
 * @param data_callback The function that will be called when a data frame is
 * received from a sender.
 * @param arg the extra argument passed to the `data_callback`
 * @return 0 on success, -1 on error
 */
RIST_API int rist_receiver_data_callback_set(struct rist_ctx *ctx,
	int (*data_callback)(void *arg, const struct rist_data_block *data_block),
	void *arg);

/* Sender specific functions, use rist_sender_create to create a sender rist_ctx */

/**
 * @brief Create Sender
 *
 * Create a RIST sender instance
 *
 * @param[out] ctx a context representing the sender instance
 * @param profile RIST profile
 * @param flow_id Flow ID, use 0 to delegate creation of flow_id to lib
 * @param logging_settings Struct containing logging settings
 * @return 0 on success, -1 in case of error.
 */
RIST_API int rist_sender_create(struct rist_ctx **ctx, enum rist_profile profile,
				uint32_t flow_id, struct rist_logging_settings *logging_settings);

/**
 * @brief Retrieve the current flow_id value
 *
 * Retrieve the current flow_id value
 *
 * @param ctx RIST sender context
 * @param flow_id pointer to your flow_id variable
 * @return 0 on success, -1 on error
 */
RIST_API int rist_sender_flow_id_get(struct rist_ctx *ctx, uint32_t *flow_id);

/**
 * @brief Change the flow_id value
 *
 * Change the flow_id value
 *
 * @param ctx RIST sender context
 * @param flow_id new flow_id
 * @return 0 on success, -1 on error
 */
RIST_API int rist_sender_flow_id_set(struct rist_ctx *ctx, uint32_t flow_id);

/**
 * @brief Write data into a librist packet.
 *
 * One sender can send write data into a librist packet.
 *
 * @param ctx RIST sender context
 * @param data_block pointer to the rist_data_block structure
 * the ts_ntp will be populated by the lib if a value of 0 is passed
 * @return number of written bytes on success, -1 in case of error.
 */
RIST_API int rist_sender_data_write(struct rist_ctx *ctx, const struct rist_data_block *data_block);

/* OOB Specific functions, send and receive IP traffic inband in RIST Main Profile */
/**
 * @brief Write data directly to a remote receiver peer.
 *
 * This API is used to transmit out-of-band data to a remote receiver peer
 *
 * @param ctx RIST context
 * @param oob_block a pointer to the struct rist_oob_block
 * @return number of written bytes on success, -1 in case of error.
 */
RIST_API int rist_oob_write(struct rist_ctx *ctx, const struct rist_oob_block *oob_block);

/**
 * @brief Reads out-of-band data
 *
 * Use this API to read out-of-band data from an internal fifo queue instead of the callback
 *
 * @param ctx RIST context
 * @param[out] oob_block pointer to the rist_oob_block structure
 * @return 0 on success, -1 in case of error.
 */
RIST_API int rist_oob_read(struct rist_ctx *ctx, const struct rist_oob_block **oob_block);

/**
 * @brief Enable out-of-band data channel
 *
 * Call after receiver initialization to enable out-of-band data.
 *
 * @param ctx RIST context
 * @param oob_callback A pointer to the function that will be called when out-of-band data
 * comes in (NULL function pointer is valid)
 * @param arg is an the extra argument passed to the `oob_callback`
 * @return 0 on success, -1 on error
 */
RIST_API int rist_oob_callback_set(struct rist_ctx *ctx,
								   int (*oob_callback)(void *arg, const struct rist_oob_block *oob_block),
								   void *arg);

/**
 * @brief Assign dynamic authentication handler
 *
 * Whenever a new peer is connected, @a connect_cb is called.
 * Whenever a new peer is disconnected, @a disconn_cb is called.
 *
 * @param ctx RIST context
 * @param connect_cb A pointer to the function that will be called when a new peer
 * connects. Return 0 or -1 to authorize or decline (NULL function pointer is valid)
 * @param disconn_cb A pointer to the function that will be called when a new peer
 * is marked as dead (NULL function pointer is valid)
 * @param arg is an the extra argument passed to the `conn_cb` and `disconn_cb`
 */
RIST_API int rist_auth_handler_set(struct rist_ctx *ctx,
		int (*connect_cb)(void *arg, const char* conn_ip, uint16_t conn_port, const char* local_ip, uint16_t local_port, struct rist_peer *peer),
		int (*disconn_cb)(void *arg, struct rist_peer *peer),
		void *arg);



/**
 * @brief Add a peer connector to the existing sender.
 *
 * One sender can send data to multiple peers.
 *
 * @param ctx RIST context
 * @param[out] peer Store the new peer pointer
 * @param config a pointer to the struct rist_peer_config, which contains
 *        the configuration parameters for the peer endpoint.
 * @return 0 on success, -1 in case of error.
 */
RIST_API int rist_peer_create(struct rist_ctx *ctx,
		struct rist_peer **peer, const struct rist_peer_config *config);

/**
 * @brief Remove a peer connector to the existing sender.
 *
 * @param ctx RIST context
 * @param peer a pointer to the struct rist_peer, which
 *        points to the peer endpoint.
 * @return 0 on success, -1 in case of error.
 */
RIST_API int rist_peer_destroy(struct rist_ctx *ctx,
		struct rist_peer *peer);

/**
 * @brief Set RIST max jitter
 *
 * Set max jitter
 *
 * @param ctx RIST context
 * @param t max jitter in ms
 * @return 0 on success, -1 on error
 */
RIST_API int rist_jitter_max_set(struct rist_ctx *ctx, int t);



/**
 * @brief Kickstart a pre-configured sender
 *
 * After all the peers have been added, this function triggers
 * the sender to start
 *
 * @param ctx RIST context
 * @return 0 on success, -1 in case of error.
 */
RIST_API int rist_start(struct rist_ctx *ctx);


/**
 * @brief Destroy RIST sender
 *
 * Destroy the RIST instance
 *
 * @param ctx RIST context
 * @return 0 on success, -1 on error
 */
RIST_API int rist_destroy(struct rist_ctx *ctx);

/**
 * @brief Parses rist url for peer config data (encryption, compression, etc)
 *
 * Use this API to parse a generic URL string and turn it into a meaninful peer_config structure
 *
 * @param url a pointer to a url to be parsed, i.e. rist://myserver.net:1234?buffer=100&cname=hello
 * @param[out] peer_config a pointer to a the rist_peer_config structure (NULL is allowed).
 * When passing NULL, the library will allocate a new rist_peer_config structure with the latest
 * default values and it expects the application to free it when it is done using it.
 * @return 0 on success or non-zero on error. The value returned is actually the number
 * of parameters that are valid
 */
RIST_API int rist_parse_address(const char *url, const struct rist_peer_config **peer_config);

/**
 * @brief Parses udp url for peer config data (multicast interface, stream-id, etc)
 *
 * Use this API to parse a generic URL string and turn it into a meaninful peer_config structure
 *
 * @param url a pointer to a url to be parsed, i.e. udp://myserver.net:1234?miface=eth0&stream-id=1968
 * @param[out] peer_config a pointer to a the rist_peer_config structure (NULL is allowed).
 * When passing NULL, the library will allocate a new rist_peer_config structure with the latest
 * default values and it expects the application to free it when it is done using it.
 * @return 0 on success or non-zero on error. The value returned is actually the number
 * of parameters that are valid
 */
RIST_API int rist_parse_udp_address(const char *url, const struct rist_peer_config **peer_config);

/**
 * @brief Set callback for receiving stats structs
 *
 * @param ctx RIST context
 * @param statsinterval interval between stats reporting
 * @param stats_cb Callback function that will be called. The json char pointer must be free()'d when you are finished.
 * @param arg extra arguments for callback function
 */
RIST_API int rist_stats_callback_set(struct rist_ctx *ctx, int statsinterval, int (*stats_cb)(void *arg, const struct rist_stats *stats_container), void *arg);

/**
 * @brief Free the rist_stats structure memory allocations
 *
 * @return 0 on success or non-zero on error.
 */
RIST_API int rist_stats_free(const struct rist_stats *stats_container);

/**
 * @brief Get the version of libRIST
 *
 * @return String representing the version of libRIST
 */
RIST_API const char *librist_version(void);

#ifdef __cplusplus
}
#endif

#endif
