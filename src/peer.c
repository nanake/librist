#include "rist-private.h"
#include "librist_config.h"
#include "peer.h"
#if HAVE_SRP_SUPPORT
#include "proto/eap.h"
#endif

#if HAVE_SRP_SUPPORT
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

bool librist_peer_should_rollover_passphrase(struct rist_peer *peer) {
	if (!peer->eap_ctx)
		return false;
	if (peer->rolling_over_passphrase) {
		if (!peer->child) {
			return rist_eap_password_sending_done(peer->eap_ctx);
		}
		bool rollover = false;
		struct rist_peer *child = peer->child;
		while (child != NULL) {
			rollover = rist_eap_password_sending_done(peer->eap_ctx);
			if (!rollover)
				break;
			child = child->sibling_next;
		}
		return rollover;
	}
	return rist_eap_may_rollover_tx(peer->eap_ctx);
}
#endif

