#ifndef LIBRIST_INTERNAL_PEER_H
#define LIBRIST_INTERNAL_PEER_H
#include "common/attributes.h"
#include "librist_config.h"
#include "socket-shim.h"
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

struct rist_peer;

#if HAVE_SRP_SUPPORT
RIST_PRIV void librist_peer_update_rx_passphrase(struct rist_peer *peer, const uint8_t *passphrase, size_t passphrase_len, bool immediate);
RIST_PRIV void librist_peer_update_tx_passphrase(struct rist_peer *peer, const uint8_t *passphrase, size_t passphrase_len, bool immediate);
RIST_PRIV void librist_peer_get_current_tx_passphrase(struct rist_peer *peer, const uint8_t **passphrase, size_t *passphrase_len);
RIST_PRIV bool librist_peer_should_rollover_passphrase(struct rist_peer *peer);
#endif

struct rist_peer * _librist_peer_match_peer_addr(struct rist_peer *p, uint16_t family, struct sockaddr *addr);

#endif /* LIBRIST_INTERNAL_PEER_H */
