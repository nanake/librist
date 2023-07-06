#include "rist-private.h"
#include "peer.h"

void librist_peer_update_rx_passphrase(struct rist_peer *peer, const uint8_t *passphrase, size_t passphrase_len, bool immediate) {
	if (immediate || !peer->supports_otf_passphrase_change) {
		_librist_crypto_psk_set_passphrase(&peer->key_rx, passphrase, passphrase_len);
		_librist_crypto_psk_set_passphrase(&peer->key_rx_odd, passphrase, passphrase_len);
	} else if (peer->supports_otf_passphrase_change) {
		if (!peer->key_rx_odd_active)
			_librist_crypto_psk_set_passphrase(&peer->key_rx, passphrase, passphrase_len);
		else
			_librist_crypto_psk_set_passphrase(&peer->key_rx_odd, passphrase, passphrase_len);
	}
}

void librist_peer_get_current_tx_passphrase(struct rist_peer *peer, const uint8_t **passphrase, size_t *passphrase_len) {
	if (peer->key_tx_odd_active) {
		_librist_crypto_psk_get_passphrase(&peer->key_tx_odd, passphrase, passphrase_len);
		return;
	}
	_librist_crypto_psk_get_passphrase(&peer->key_tx, passphrase, passphrase_len);
}

void librist_peer_update_tx_passphrase(struct rist_peer *peer, const uint8_t *passphrase, size_t passphrase_len, bool immediate) {
	if (immediate || !peer->supports_otf_passphrase_change) {
		_librist_crypto_psk_set_passphrase(&peer->key_tx, passphrase, passphrase_len);
		_librist_crypto_psk_set_passphrase(&peer->key_tx_odd, passphrase, passphrase_len);
	} else if (peer->supports_otf_passphrase_change) {
		if (!peer->key_rx_odd_active)
			_librist_crypto_psk_set_passphrase(&peer->key_tx, passphrase, passphrase_len);
		else
			_librist_crypto_psk_set_passphrase(&peer->key_tx_odd, passphrase, passphrase_len);
	}
}
