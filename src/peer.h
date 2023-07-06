#include "common/attributes.h"
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

struct rist_peer;

RIST_PRIV void librist_peer_update_rx_passphrase(struct rist_peer *peer, const uint8_t *passphrase, size_t passphrase_len, bool immediate);
RIST_PRIV void librist_peer_update_tx_passphrase(struct rist_peer *peer, const uint8_t *passphrase, size_t passphrase_len, bool immediate);
RIST_PRIV void librist_peer_get_current_tx_passphrase(struct rist_peer *peer, const uint8_t **passphrase, size_t *passphrase_len);
